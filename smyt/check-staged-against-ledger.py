#!/usr/bin/env python3
"""Check staged release artifacts against the signing ledger.

WHAT THIS ANSWERS, and it is the only question worth asking of a signed release: are the bytes that
are PUBLISHED the bytes that were SIGNED? Nothing else in the chain establishes that. A signature says
a file is the one that was signed; the ledger says what was signed. Only comparing the two says they
are the same file.

Why it takes a staged directory rather than a release: the ledger records PATHS, so the check needs the
files at a path that still exists. That is the whole reason the signing flow stages into
build-artifacts\\signed\\<repo>\\<tag>\\ and not into a temp directory -- signing in temp is how a
ledger becomes a list of dead pointers.

Usage:
    python check-staged-against-ledger.py <staged-dir> [<staged-dir> ...]

Exit code 0 when every file with a ledger record matches, 1 otherwise. A file with no ledger record is
reported and does not by itself fail the run: it means the ledger never saw that file, which is worth
knowing but is a different fact.
"""

import hashlib
import json
import os
import sys

LEDGER = r'E:\DaShaoHuo\build-artifacts\signing\smyt-signings.ndjson'


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest().upper()


def load_ledger(path=LEDGER):
    """Every record, and the LAST record per basename: a file signed twice is described by its later
    signature, and comparing against the earlier one would report a mismatch that means nothing."""
    records = []
    if os.path.exists(path):
        with open(path, encoding='utf-8') as fh:
            for line in fh:
                if line.strip():
                    records.append(json.loads(line))
    last = {}
    for r in records:
        f = r.get('file') or r.get('path')
        if f:
            last[os.path.basename(f)] = r
    return records, last


def main(dirs):
    records, last = load_ledger()
    print('  ledger: %d record(s), %d distinct file name(s)' % (len(records), len(last)))
    print()

    total = matched = differing = unrecorded = 0
    problems = []
    for d in dirs:
        if not os.path.isdir(d):
            print('  skip (not a directory): %s' % d)
            continue
        print('  %s' % d)
        print('  %-36s %-18s %-18s %s' % ('file', 'staged sha256', 'ledger sha256_signed', 'verdict'))
        for name in sorted(os.listdir(d)):
            p = os.path.join(d, name)
            if not os.path.isfile(p):
                continue
            total += 1
            mine = sha256_of(p)
            rec = last.get(name)
            if not rec:
                unrecorded += 1
                print('  %-36s %-18s %-18s %s' % (name, mine[:16], '(no record)', 'not in the ledger'))
                continue
            theirs = (rec.get('sha256_signed') or '').upper()
            if mine == theirs:
                matched += 1
                print('  %-36s %-18s %-18s %s' % (name, mine[:16], theirs[:16], 'same bytes'))
            else:
                differing += 1
                print('  %-36s %-18s %-18s %s' % (name, mine[:16], theirs[:16], 'DIFFERENT'))
                problems.append('%s: staged %s, ledger %s' % (name, mine, theirs))
        print()

    print('  %d file(s): %d same bytes, %d different, %d not in the ledger' % (total, matched, differing, unrecorded))
    if problems:
        print()
        for p in problems:
            print('  DIFFERENT  %s' % p)
        return 1
    return 0


if __name__ == '__main__':
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(args))
