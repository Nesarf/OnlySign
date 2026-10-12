"""The command line, which is the engine with a keyboard instead of a window.

The window will call the same three functions this calls -- ``discover.scan``, ``preview`` and
``execute`` -- so anything that can be done from here can be done from there, and the tests that
cover this cover both.

    python -m onlysign scan  <project>            propose artifacts, with the reason for each
    python -m onlysign certs                      what could sign
    python -m onlysign sign  <file>...            sign, and record what was signed
    python -m onlysign check                      compare the ledger against the files
    python -m onlysign trust                     show what the trust stores hold

Exit codes are meant to be used: 0 when everything asked for happened, 1 when something did not, and
2 for a usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from . import notice
from . import phrases
from .notice import text as notice_text
from .engine import audit, certs, discover, gate, ledger, pe, signer, trust, workflow


def _print_certificates() -> int:
    certificates = certs.list_certificates()
    if not certificates:
        print("no certificate on this machine has a private key, so nothing here can sign.")
        print("A self-signed one can be made with:  python -m onlysign certs --create \"CN=Your Name\"")
        return 0
    for certificate in certificates:
        state = "expired" if certificate.expired else f"{certificate.days_left()} days left"
        flags = []
        if not certificate.permits_code_signing:
            flags.append("does not permit code signing")
        if certificate.self_signed:
            flags.append("self-signed")
        if not certificate.usage_restricted:
            flags.append("no usage restriction")
        note = ("  (" + ", ".join(flags) + ")") if flags else ""
        print(f"{certificate.thumbprint}")
        print(f"    {certificate.subject}")
        print(f"    {state}, in {certificate.store}{note}")
    return 0


def _create_certificate(subject: str, years: int, out_dir: str) -> int:
    os.makedirs(out_dir, exist_ok=True)
    stem = "".join(ch if ch.isalnum() else "-" for ch in subject.split("CN=")[-1]) or "certificate"
    pfx = os.path.join(out_dir, stem + ".pfx")
    cer = os.path.join(out_dir, stem + ".cer")
    password = _random_password()
    certificate = certs.create_self_signed(subject, years=years, password=password,
                                           pfx_path=pfx, cer_path=cer)
    print(f"created {certificate.subject}")
    print(f"  thumbprint : {certificate.thumbprint}")
    print(f"  valid to   : {certificate.not_after.date()}")
    print(f"  cer        : {cer}   (the public half -- this is the one to publish)")
    print(f"  pfx        : {pfx}   (the private key -- never publish this)")
    print(f"  password   : {password}")
    print()
    print("The password is shown once and is not stored anywhere; write it down now.")
    print("The key file's permissions have been narrowed to your account, the administrators and "
          "the system.")
    return 0


def _random_password() -> str:
    import base64
    import secrets
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def _cmd_scan(args: argparse.Namespace) -> int:
    result = discover.scan(args.repo, args.artifacts)
    if args.json:
        print(json.dumps({
            "repo": result.repo,
            "examined": result.examined,
            "notes": result.notes,
            "candidates": [candidate.__dict__ for candidate in result.candidates],
        }, ensure_ascii=False, indent=2))
        return 0
    print(f"examined {result.examined} file(s) under {result.repo or args.artifacts}")
    if result.candidates:
        by_source = result.by_source()
        print("found " + ", ".join(f"{count} by {source}" for source, count in sorted(by_source.items())))
        print()
    for candidate in result.candidates:
        print(candidate.describe())
    for note in result.notes:
        print(f"\nnote: {note}")
    return 0


def _cmd_certs(args: argparse.Namespace) -> int:
    if args.create:
        return _create_certificate(args.create, args.years, args.out)
    return _print_certificates()


def _cmd_sign(args: argparse.Namespace) -> int:
    paths = list(args.paths)
    if args.repo or args.artifacts:
        result = discover.scan(args.repo or os.getcwd(), args.artifacts)
        proposed = [candidate.path for candidate in result.candidates if candidate.selected]
        if not proposed:
            print("the scan proposed nothing to sign; nothing was done.")
            for note in result.notes:
                print(f"  note: {note}")
            return 1
        print(f"the scan proposed {len(proposed)} artifact(s):")
        for candidate in result.candidates:
            if candidate.selected:
                print(f"  {os.path.basename(candidate.path)}  -- {candidate.reason}")
        print()
        paths += proposed

    if not paths:
        print("nothing to sign: name some files, or a --repo to scan.", file=sys.stderr)
        return 2

    try:
        certificate = certs.resolve(args.cert)
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    plan = workflow.Plan(
        paths=paths,
        thumbprint=certificate.thumbprint,
        note=args.note,
        ledger_path=args.ledger,
        allow_untimestamped=args.allow_untimestamped,
        force=args.force,
        backend=args.backend,
        output_dir=args.output,
        trust=args.trust,
    )

    for line in workflow.preview(plan):
        print(line)
    print()

    if args.dry_run:
        print("dry run: nothing was signed and nothing was written. Drop --dry-run to do it.")
        return 0

    outcome = workflow.execute(plan, dry_run=False, progress=lambda message: print(f"  {message}"))
    print()
    print(outcome.summary())
    print(f"ledger: {plan.ledger_at()}")
    for line in workflow.describe_outcome(outcome):
        print(line)

    closing = phrases.table(getattr(args, "language", ""))
    print()
    print(closing.get("signing_failed" if outcome.failed else "bonfire", ""))
    return 1 if outcome.failed else 0


def _cmd_gate(args: argparse.Namespace) -> int:
    """Write the gate that travels with a signed package.

    This is the other half of signing: a signature is only worth something to somebody who can
    check it, and the person pulling a package is exactly that somebody. The gate pins the signer,
    says who made the tool only once the signature agrees, and asks once before installing.
    """
    artifact = os.path.abspath(args.artifact)
    if not os.path.isfile(artifact):
        print(f"no such file: {artifact}", file=sys.stderr)
        return 2

    if args.cert:
        try:
            thumbprint = certs.resolve(args.cert).thumbprint
        except LookupError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    else:
        # No certificate named, so the pin comes from whoever signed the package. That is the honest
        # default: a gate should vouch for the identity that is actually on the file.
        own = signer.own_signature(artifact)
        if not own.present:
            print(f"{os.path.basename(artifact)} carries no signature, so there is nothing to pin. "
                  f"Sign it first, or name a certificate with --cert.", file=sys.stderr)
            return 1
        thumbprint = own.thumbprint

    notice = None
    if args.notice:
        if not os.path.isfile(args.notice):
            print(f"no notice file at {args.notice}", file=sys.stderr)
            return 2
        with open(args.notice, "r", encoding="utf-8") as handle:
            notice = handle.read()

    ready, checks = gate.check(artifact, thumbprint=thumbprint)
    for line in checks:
        print(f"  {line}")
    if not ready:
        print("\nThe gate was not written: a package that cannot pass its own check should not be "
              "handed one.", file=sys.stderr)
        return 1

    if notice is None:
        notice = notice_text(getattr(args, "language", ""))
    written = gate.emit(artifact, thumbprint=thumbprint, directory=args.dir, notice=notice,
                        developer=args.developer, language=getattr(args, "language", ""))
    print()
    for line in gate.describe(written):
        print(line)
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    path = args.ledger or os.path.join(os.getcwd(), ".onlysign", "signings.ndjson")
    if not os.path.isfile(path):
        print(f"no ledger at {path}")
        return 1
    report = audit.audit(path)
    if args.json:
        print(json.dumps({
            "ledger": path,
            "summary": audit.summarise(report),
            "findings": [{
                "name": finding.name, "verdict": finding.verdict, "when": finding.when,
                "path": finding.record.get("file"), "note": finding.record.get("note"),
            } for finding in report.findings],
        }, ensure_ascii=False, indent=2))
        return 0
    for finding in report.findings:
        print(f"[{finding.when}] {finding.name}  {finding.verdict.upper()}")
        print(f"     recorded : {finding.record.get('sha256_signed')}")
        if finding.current_hash:
            print(f"     on disk  : {finding.current_hash}")
        if finding.replaced_by:
            print(f"     replaced by: {str(finding.replaced_by.get('t'))[:19]}  "
                  f"{finding.replaced_by.get('note') or ''}")
        if finding.record.get("note"):
            print(f"     note     : {finding.record['note']}")
    print()
    print(audit.summarise(report))
    return 1 if report.needing_attention() else 0


def _cmd_trust(args: argparse.Namespace) -> int:
    try:
        certificate = certs.resolve(args.cert)
    except LookupError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(f"certificate: {certificate.subject}")
    print(f"           {certificate.thumbprint}")
    print()
    for state in trust.counts(certificate.thumbprint):
        print(f"  {state.store:<40} {state.count}")
    print()
    print(f"meaning: {trust.verdict(certificate.thumbprint)}")
    print()

    if args.install == workflow.TRUST_NONE:
        return 0
    scope = trust.SCOPE_MACHINE if args.install == workflow.TRUST_MACHINE_BOTH else trust.SCOPE_USER
    publishers = args.install in (workflow.TRUST_USER_PUBLISHERS, workflow.TRUST_USER_BOTH,
                                  workflow.TRUST_MACHINE_BOTH)
    roots = args.install in (workflow.TRUST_USER_ROOT, workflow.TRUST_USER_BOTH,
                             workflow.TRUST_MACHINE_BOTH)
    if args.dry_run:
        print(f"dry run: would install into "
              f"{'publisher and root' if publishers and roots else 'publisher' if publishers else 'root'} "
              f"stores for {scope}")
        return 0
    try:
        written = trust.install(certificate.thumbprint, scope=scope, publishers=publishers,
                                roots=roots, cer_path=args.cer)
    except (PermissionError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    for store in written:
        print(f"installed into {store}")
    print()
    print(f"meaning: {trust.verdict(certificate.thumbprint)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="onlysign",
        description="Sign local build artifacts, and be able to say later what was signed.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="propose the artifacts in a project")
    scan.add_argument("repo", nargs="?", default="", help="the project directory")
    scan.add_argument("--artifacts", default="", help="a directory to take at its word")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=_cmd_scan)

    cer = sub.add_parser("certs", help="what could sign")
    cer.add_argument("--create", default="", metavar="SUBJECT",
                     help='make a self-signed certificate, e.g. --create "CN=Your Name"')
    cer.add_argument("--years", type=int, default=5)
    cer.add_argument("--out", default=".", help="where the .pfx and .cer are written")
    cer.set_defaults(func=_cmd_certs)

    sign = sub.add_parser("sign", help="sign artifacts, and record what was signed")
    sign.add_argument("paths", nargs="*", default=[])
    sign.add_argument("--repo", default="", help="scan this project and sign what it proposes")
    sign.add_argument("--artifacts", default="", help="sign what is in this directory")
    sign.add_argument("--cert", default="", help="thumbprint, a prefix of one, or part of a subject")
    sign.add_argument("--note", default="", help="recorded with each signing")
    sign.add_argument("--ledger", default="", help="where the record is kept")
    sign.add_argument("--output", default="", help="copy signed artifacts here as well")
    sign.add_argument("--trust", default=workflow.TRUST_NONE, choices=workflow.TRUST_CHOICES)
    sign.add_argument("--backend", default=signer.BACKEND_POWERSHELL,
                      choices=(signer.BACKEND_POWERSHELL, signer.BACKEND_SIGNTOOL))
    sign.add_argument("--force", action="store_true", help="sign a file that is already signed")
    sign.add_argument("--allow-untimestamped", action="store_true",
                      help="accept a signature that stops verifying when the certificate expires")
    sign.add_argument("--dry-run", action="store_true", help="show what would happen and stop")
    sign.set_defaults(func=_cmd_sign)

    check = sub.add_parser("check", help="compare the ledger against the files on disk")
    check.add_argument("--ledger", default="")
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=_cmd_check)

    gate_parser = sub.add_parser(
        "gate", help="write the gate that travels with a signed package",
        description="Write the files a person runs when they pull this package: a notice, a check "
                    "of the signature the package carries, and one question before it installs.")
    gate_parser.add_argument("artifact", help="the signed file the gate will guard")
    gate_parser.add_argument("--cert", default="",
                             help="the identity to pin; without it, whoever signed the artifact")
    gate_parser.add_argument("--dir", default="", help="where to write the gate; beside the artifact by default")
    gate_parser.add_argument("--notice", default="", help="a notice file of your own")
    gate_parser.add_argument("--developer", default="its publisher",
                             help="the name used when no notice file is there to say it")
    gate_parser.set_defaults(func=_cmd_gate)

    tru = sub.add_parser("trust", help="show or change which trust stores hold a certificate")
    tru.add_argument("--cert", default="", help="thumbprint, a prefix of one, or part of a subject")
    tru.add_argument("--install", default=workflow.TRUST_NONE, choices=workflow.TRUST_CHOICES)
    tru.add_argument("--cer", default="", help="a public certificate file to install from")
    tru.add_argument("--dry-run", action="store_true")
    tru.set_defaults(func=_cmd_trust)
    return parser


def take_language(arguments: list[str]) -> tuple[list[str], str]:
    """Pull ``--lang`` out of the arguments wherever it appears.

    Doing it here rather than declaring the option on every subcommand is not laziness: argparse
    accepts an option before the command or on it, and never both, so a person typing
    ``onlysign gate x --lang zh`` would be told the argument is unrecognised if the option lived
    only on the top level. A flag that works in one of the two places it looks natural belongs in
    neither.
    """
    spoken, rest, index = "", [], 0
    while index < len(arguments):
        item = arguments[index]
        if item == "--lang" and index + 1 < len(arguments):
            spoken = arguments[index + 1]
            index += 2
            continue
        if item.startswith("--lang="):
            spoken = item.split("=", 1)[1]
            index += 1
            continue
        rest.append(item)
        index += 1
    return rest, spoken


def main(argv: list[str] | None = None) -> int:
    arguments, spoken = take_language(list(sys.argv[1:] if argv is None else argv))
    parser = build_parser()
    args = parser.parse_args(arguments)
    args.language = spoken

    # A person who typed a command is owed a sentence about what they just ran. A pipe is not, and
    # neither is anything asking for JSON -- a banner in a machine-readable stream is a bug, not
    # friendliness, so it appears only when somebody is watching and nothing was asked for in a
    # form that has to stay parseable.
    notice.show(quiet=("--json" in arguments or "--quiet" in arguments), spoken=spoken)

    if args.command == "sign" and not args.cert:
        print("--cert is required: signing names an identity, and none was named.", file=sys.stderr)
        print("Run 'onlysign certs' to see what is available.", file=sys.stderr)
        return 2
    if args.command == "trust" and not args.cert:
        print("--cert is required.", file=sys.stderr)
        return 2
    try:
        return int(args.func(args))
    except (LookupError, NotADirectoryError, PermissionError, ValueError) as exc:
        print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
