# Signing S.M.Y.T. builds

Signing anything S.M.Y.T. makes or funds, so Windows attributes it to **S.M.Y.T.** rather than to
an unknown publisher. Verified working end to end on this machine.

## Why self-signed, and not a commercial certificate

A certificate's **organization** field is written by whoever *issues* the certificate. That single
fact decides this whole question.

A commercial certificate authority fills `O=` in from a **verified legal entity** — it asks for
company registration papers. An unaligned academic seminar is not merely unable to buy such a
certificate cheaply; it is **outside what that system describes**. So `O=S.M.Y.T.` is not the
consolation prize for not having paid. It is the only form of certificate that can state the truth
about who made this.

The commercial route costs more than money:

| | Commercial CA | Self-signed |
|---|---|---|
| organization field | from a verified **company** | your own declaration |
| root of trust | the CA's, private and unauditable | **yours, and you hold it** |
| revocation | the CA can revoke, unilaterally | nobody can, and nobody needs to |
| dependency | a third party that can charge, change terms, or disappear | **none** |
| verifies where the certificate is trusted | yes | yes |
| verifies on a stranger's machine | yes | **no** |
| removes a SmartScreen warning | yes | **no** |

Handing the root of trust to a company, and accepting its ruling on whether you count as an entity,
is a strange thing for a tool whose purpose is taking other people's binaries apart. The columns are
not better and worse; they are a choice about **who holds the trust**, and this project holds its
own.

What that costs, said plainly so nobody is misled: a stranger's Windows will not verify these
signatures and will not stop warning about the download. What the signature proves — on a machine
that trusts the certificate, and to anyone who compares the hash against the signing record — is
that the build came from S.M.Y.T. and has not been altered since.

## What is here

```
signing/
  smyt-common.ps1     the parts all three scripts share: environment guard, hashing, identity, ledger
  smyt-sign.ps1       create the certificate, sign, verify, check, status, trust, untrust, read the log
  smyt-blob.ps1       sign a release artifact that is not a PE - a tarball, a data file - as a PKCS#7
                      signature, recorded in the same ledger
  smyt-release.ps1    build -> sign -> verify -> hash -> optionally publish, each step checked;
                      this is the local path, and release-nanodesu.ps1 wraps it for one project
  sign-github-release.ps1  the release path as it is actually run: stage under build-artifacts/signed
                      so the recorded paths keep existing, sign, verify, hash, then publish. One run
                      per directory: a .download.lock naming a live pid makes a second run refuse
                      before it downloads anything, because an interrupted one leaves its gh child
                      holding a 73 MB file and the next run would blame the wrong process
  check-staged-against-ledger.py  are the bytes about to be published the bytes that were signed
  cert-state.ps1      where the certificate is, and whether asking works at all -- every count is
                      paired with a count that must be non-zero, because a PS7-shadowed module path
                      makes Cert: answer 0 for every store, which reads exactly like an empty store
  smyt-selftest.ps1   runs the toolchain against itself, in a scratch directory
  release-nanodesu.ps1  Nanodesu's paths, as one command
  release-mega.ps1    mega-index-map's paths, as one command: preconditions, pack, sign, verify,
                      archive, tag, publish - each step checked before the next
  publish-checksums.ps1  the artifacts an Authenticode signature cannot reach: writes SHA256SUMS.txt
                      from the release's own digests -- never from a local copy, so "the list was
                      made before the signing" stops being a mistake anyone can make -- signs it
                      with the Ed25519 key, publishes the list, the detached signature and an
                      allowed_signers file, then re-reads the release to prove what landed
  publish-release.ps1 one command for the whole signing tail, in the only order that works: the PEs
                      through sign-github-release.ps1, then the list. Each half runs in its own
                      process, so a refusal in step 1 stops the run instead of publishing a list
                      over bytes that are about to be replaced
  smyt-codesign.pfx   certificate WITH private key   (secret — never publish)
  smyt-codesign.cer   public certificate only        (publish freely)
  pfx-password.sealed random password for the pfx    (secret, SEALED — the plaintext form was deleted
                      on 2026-10-13; a `.sealed` file is an AES-256-GCM container whose key is
                      DPAPI-protected for this machine. ACL-restricted as well: SYSTEM, Administrators
                      and this account, with Users and Authenticated Users absent)
  smyt-signings.ndjson  append-only record of every signing
  mark/               the F.D.C.U.S. emblem, the application icon, and the anarcho-communist mark
  README.md           this file

  history/            not created yet: it is for superseded certificates, and none has been
                      superseded. Listed here so that its absence reads as "nothing to keep" rather
                      than as a file somebody forgot.
```

The certificate:

```
subject   : O=S.M.Y.T., CN=S.M.Y.T. Code Signing
key       : RSA 3072, SHA-256
valid for : 5 years
EKU       : Code Signing
```

There is deliberately **no country field**. S.M.Y.T. claims no nationality, and writing one would be
a false statement of exactly the kind a signature is supposed to prevent.

## The marks, and F.D.C.U.S.

```
mark/fdcus-mark.png             white ink on transparency, 1452 px  — for dark backgrounds
mark/fdcus-mark-ink.png         the same shape in near-black        — for light backgrounds
mark/fdcus-mark-256.png         white, 256 px                       — release pages, small UI
mark/fdcus.ico                  the Windows application icon, 16 to 256 px
mark/fdcus-icon-preview.png     the 256 px icon on a light plate    — for looking at
mark/circle-a-hammer.png        the anarcho-communist mark, transparent, 828 px
mark/circle-a-hammer-256.png    the same at 256 px
mark/build-icon.py              rebuilds the .ico from fdcus-mark.png (needs Pillow)
```

### The F.D.C.U.S. emblem

The emblem is three objects crossed: an **umbrella** (伞), a **sword** (剑) and a **violin bow**
(琴弓). Above them, in blackletter, the wordmark **F.D.C.U.S.** — five letters for five words:

| | | |
|---|---|---|
| **F** | Freedom | |
| **D** | Dream | |
| **C** | Communism | |
| **U** | Unyielding | |
| **S** | Soul | |

The source file is white ink, with the shape living entirely in the **alpha channel** and black RGB
left underneath it. Two consequences worth knowing: it is invisible on a white background — that is
the artwork, not a broken file — and black RGB under transparent pixels produces dark fringes the
moment anything scales or composites it. The copies here have that area scrubbed and the ink centred
on a square canvas.

### The application icon

```powershell
python mark\build-icon.py      # rebuilds fdcus.ico from fdcus-mark.png
```

Three decisions are in that build, and they are decisions rather than settings:

* **a dark tile, not a bare glyph** — the mark is white ink, so on its own it disappears against a
  light taskbar; on a near-black rounded square it reads either way
* **different art below 48 px** — blackletter at 16 px is not small text, it is noise, so those
  sizes carry the three objects alone, scaled larger
* **a hand-assembled .ico** — Pillow resizes one image into every size of an ICO, and each size
  here is composed differently, so the container is written directly as a directory of PNG frames

`-Build` passes it to PyInstaller as `--icon` and prints which file it used; `-NoIcon` builds
without one and `-Icon <path>` uses another. A built executable is the only place inside an
artifact where the mark can appear at all — the next section says why.

### The anarcho-communist mark

`circle-a-hammer.png` is S.M.Y.T.'s anarcho-communist mark: the circled A with a hammer, in magenta
and cyan. It arrived flattened onto a white background, and that background was removed by solving
the blend rather than by thresholding — a pixel on white is `C = A·F + (1−A)·255`, and both inks
here have a channel at zero, so `A = 1 − min(C)/255` and the ink colour follows by division. That is
what stops the 32,455-pixel anti-aliased edge from becoming a white halo, which a threshold would
have left behind and which would only have shown up on a dark background. The 256 px copy is resized
in premultiplied alpha for the same reason.

### Hashes

Identity material should be as pinned as the certificate is, so that a changed mark is visible here
rather than noticed by comparing two releases.

```
fdcus-mark.png            78DE8BC80412869FF8C72ABDA2324EA9D4B080DCDC25712AB9F9E3570606DD2C
fdcus-mark-ink.png        3CDC6E5F41A63B5A2534F03CF9B0307AEF91C9B5DDC0A763B9EC10BD882FD965
fdcus-mark-256.png        1C0F3EFBBCC9458FCBD451F773571EDEFDB8FCD0AB378D5E8BE958422A998C4A
fdcus.ico                 AFB27549CDF9DBA401A95EFA13744C6EEA4CEAF0982EFEA6B3A47BC379997DF1
circle-a-hammer.png       082FC827162960856302886D87485EAACAA17B8FEC6F5522748AFD3702BD5CB5
circle-a-hammer-256.png   466F416332D18BBE437A9B3ED87D9E502B0E44230051179678FD430BD704DA1C
source, F.D.C.U.S.        22C8D167D322B3C3AEEA4245E0D3B3AD80B3103C96EED4116568D4A7FC67A899
source, anarcho-communist EDEAA359B3770EDAD61DEE7555FA49D63C70CBE8E38301823033A267CABBB2EF
```

### Where the mark can and cannot go in a signature

An embedded Authenticode signature has exactly two fields carrying anything a person reads: the
**description** (`/d`) and the **description URL** (`/du`), both shown on the file's Digital
Signatures tab. There is no field for an image and no way to put a logo inside the signature.

So the wordmark can travel in the signature as text and the emblem has to live where images live:
the application's own icon at build time, the release page, and this directory. That is a property
of the format rather than a choice — stated so nobody goes looking for the logo in a property sheet.

## The two trust stores, and which one does the work

This is the part that is easy to get wrong, and it was wrong here for a while: the certificate was
in `TrustedPublisher` in both hives and in neither `Root`, which is a combination that verifies
nothing at all.

**Trusted Root Certification Authorities** is the store of trust *anchors*. Windows builds a chain
from the signer upward and asks whether it ends somewhere it trusts. A self-signed certificate is
its own root, so this is the store that decides the verdict. Nothing else can substitute for it.

**Trusted Publishers** is a statement that this publisher is one you accept — it is consulted by
installers and by some policies. It is not an anchor. With the certificate only here,
`Get-AuthenticodeSignature` still reports `UnknownError`.

So the answer is **both**, and the order they are usually installed in is the reverse of the order
they matter in — because the store that changes nothing installs silently, while the one that
decides requires a person to agree to it. There is a certain justice in that.

```powershell
.\smyt-sign.ps1 -InstallTrust                 # this account; TrustedPublisher installs silently
.\smyt-sign.ps1 -InstallTrust -IncludeRoot    # also the root; Windows asks you to confirm
.\smyt-sign.ps1 -MachineTrust                 # all accounts on this machine; needs an elevated session
.\smyt-sign.ps1 -TrustHelp                    # opens the certificate wizard and prints the steps
.\smyt-sign.ps1 -RemoveTrust                  # undo, and report what is actually left
```

`-InstallTrust` on its own leaves the root alone on purpose — the consent prompt is the defence
against a program installing its own root of trust, and it is not scripted around. It says so, and
`-Status` then reports the verdict rather than a promise.

### Why machine level, and what it means

`LocalMachine\Root` can be written without a prompt **when the session is already elevated**: the
elevation *is* the consent. Both of these are true and both matter:

* writing it from an already-elevated session is legitimate, and is what administration is
* it trusts the certificate **for every account on the machine**, which is right for a build machine
  and wrong for a shared one

A root store is a claim of authority, and S.M.Y.T. wanting none is a reason to be careful with it:
the certificate is a trust anchor only for as long as it signs software and never issues another
certificate. Keep that discipline and "this machine trusts S.M.Y.T." means exactly "this machine
trusts things S.M.Y.T. signed", which is all that was ever wanted. `-RemoveTrust` exists for the
other case, and reports the resulting state of all four stores rather than a count of its own
successes.

## Everyday use

```powershell
# sign one or more files; each signing is recorded
.\smyt-sign.ps1 -Sign build\app.exe -Note "release 1.2.0"
.\smyt-sign.ps1 -Sign a.exe, b.exe

# check a signature, and check it against the ledger
.\smyt-sign.ps1 -Verify build\app.exe
.\smyt-sign.ps1 -CheckFile build\app.exe

# what has been signed, and whether it is still true
.\smyt-sign.ps1 -Log -Last 20
.\smyt-sign.ps1 -Check

# the state of the certificate, the four stores and the ledger
.\smyt-sign.ps1 -Status

# re-apply the ACLs to the key material, the ledger and this directory
.\smyt-sign.ps1 -Protect
```

Signing uses the private key **from the certificate store**, not through the pfx, so no password is
ever placed on a command line where every process on the machine could read it. The pfx is the
offline backup of the key. If the certificate is not in the store the script says so and falls back
to the pfx, warning that the password will be visible for as long as signtool runs.

Two things are refused rather than done quietly:

* signing a file that **already carries a signature** — Authenticode appends instead of replacing,
  so a second signature would leave a ledger record whose "before signing" hash is the previous
  signature's output. Pass `-Force` if that is what you mean.
* signing with **no timestamp**, when every timestamp authority is unreachable. Measured behaviour:
  signtool exits non-zero and leaves the file exactly as it found it, so nothing is half-done.
  `-AllowUntimestamped` signs anyway, and the record is marked.

The signer is pinned by **thumbprint**, read from the published `.cer`, in the signing path, in the
release check and in the ledger. A subject string would have been a spelling anyone can reuse.

Three timestamp authorities are tried in order, because one URL is a single point of failure for a
step that is treated as fatal. The authority that answered is recorded in the ledger.

### Signing something that is not a PE

`smyt-blob.ps1` exists for artifacts with no PE image to write into: a package tarball, a source archive, a
data file. It asks signtool for a PKCS#7 signature instead of an embedded one, and keeps everything else the
same - the key comes from the certificate store via `/sha1 <thumbprint>`, three timestamp authorities are tried
in order, and the signing lands in `smyt-signings.ndjson` with the same field names. A blob record sets
`sha256_signed = sha256_unsigned`, because the artifact is left byte-identical, and its note says
"detached PKCS#7" so the two kinds are told apart when reading the ledger.

Three facts measured while building it (2026-10-15), each of which cost a wrong conclusion first:

* **`signtool verify /p7` cannot be combined with `/pa`** - it answers "The /p7 option is incompatible with
  the /pa option". Without `/pa` it runs, and with a self-signed certificate it reports trust errors on a
  signature whose bytes are perfectly intact ("Number of errors: 2"). So the blob path verifies
  cryptographically: decode the PKCS#7, check the signature, and require the signer's thumbprint to be the
  published one.
* **`SignedCms.CheckSignature` returns void** - failure is an exception, not a false return. Written as
  `if (-not $cms.CheckSignature($true))` it reads every good signature as invalid, because `-not $null` is
  true. This is the kind of bug that looks like a broken signature rather than a broken check.
* **The `/p7` output carries its own copy of the signed bytes** - 359 KB in produced a 367 KB `.p7s`. So
  verifying the signature alone only says the copy *inside* the file is intact: a tarball with one byte
  flipped still verified. The bytes on disk are compared with the copy inside the signature before the
  signature itself is checked.

A detached signature is not Authenticode: Windows shows no Digital Signatures tab for a `.p7s`, SmartScreen
ignores it, and none of the trust-store machinery applies. The certificate is self-signed, so it verifies on a
machine that has imported it and not on a stranger's. That is the same trade the PE path makes, stated here so
nobody discovers it by surprise.

## The whole release, in one command

```powershell
.\smyt-release.ps1 -Build -Source E:\path\to\tool.py `
                   -Publish -Repo Nesarf/Nanodesu -Tag v1.2.0 `
                   -Note "release 1.2.0"
```

Steps, each one checked rather than assumed:

| step | what is verified |
|---|---|
| build | the file exists after PyInstaller reports success |
| sign | signtool exits 0 **and a timestamp was actually obtained** |
| verify | the signature is present and its thumbprint is the published one |
| hash | recorded before and after signing (Authenticode changes the file) |
| publish | **GitHub's reported digest equals the local one, for every asset uploaded** |

The last check is the one that matters most. An upload that truncated or re-encoded would otherwise
be indistinguishable from a good one, and the whole point of publishing a hash is that it matches.
That is also why the `.sha256` and the public `.cer` are uploaded with the build: a hash nobody can
obtain is not a check, and a signature nobody can verify against a pinned certificate is a claim.
The `.sha256` is written in the standard `<hash>  <name>` form so `sha256sum -c` can read it.

**Sign last is not a preference.** An Authenticode signature covers the whole PE file, so any later
rewrite of the contents destroys it. Verified: repacking a signed binary yields an unsigned one.

One honest note about the table above: the first four rows have been exercised repeatedly. The
**publish** row has not been run since it was rewritten to upload three assets and verify each
digest — the local half of it is checked, the GitHub half is not. Treat it as untested until
somebody runs it against a real tag, and say so if it turns out to be wrong.

`-OutDir` is refused unless it is inside `E:\DaShaoHuo\`, and a drive root is refused always. Step 1
removes the output directory recursively, and a path that came from a command line is one typo away
from an empty disk. `-AllowAnywhere` overrides it deliberately, not accidentally.

## The signing record

Every signing appends one line to `smyt-signings.ndjson`: the file, its size, its SHA-256 **as
signed**, its SHA-256 **before** signing, the signer, the thumbprint, whether a timestamp was
obtained, which authority provided it, the note, and the hash of the previous line.

Two hashes because Authenticode appends a certificate table, so signing changes the file. "Which
bytes we signed" and "what the file was before we signed it" are different questions, and both get
asked.

```json
{"t":"2026-10-11T17:59:01.1Z","file":"E:\\...\\汉堡店修改器-安装程序.exe","name":"汉堡店修改器-安装程序.exe",
 "size":1165528,"sha256_signed":"BDAE633A...","sha256_unsigned":"9C31F0A2...",
 "signer":"O=S.M.Y.T., CN=S.M.Y.T. Code Signing","thumbprint":"4EA54E72...",
 "timestamped":true,"tsa":"http://timestamp.digicert.com","note":"汉堡店修改器 v1.0.3 安装程序",
 "prev":"3F1B..."}
```

Three things about this file that are easy to lose:

* **It is UTF-8 without a BOM, and it is read as UTF-8.** Reading it with the machine's ANSI code
  page (936 here) turns a Chinese note into mojibake and, because the last character's tail byte
  pairs with the closing quote, makes the line unparseable JSON — one character costing a whole
  record. That is exactly what `-Log` used to do. Both sides now pin the encoding.
* **Each record carries the hash of the line before it**, so an edit to the ledger shows up as a
  broken chain rather than as silence. Records written before this existed are reported as
  unchained; the first record of a chain links to nothing and is the start, not a hole.
* **The `file` field is a path, which is an address and not an identity.** Several records can name
  the same path — a rebuild overwrites the previous build — so the hash is what says which file a
  record is about. `-CheckFile` answers with all the records that touch a path.
* **A publication is a second record, not an edit to the first.** Publishing appends
  `{"event":"published", …}` naming the tag, the URL and the same hash, because the chain only means
  something while past lines are never rewritten. `-CheckFile <file>` prints it under the signing
  records for that path, which is how "which release is this build?" got an answer.

Appending is also the one operation two release processes can collide on, and a collision used to
look like tampering: each record names the line before it, so if both signers read the tip and then
both wrote, the second record pointed at a line that was no longer its predecessor and the chain
reported a fork on a ledger nobody had touched. That was demonstrated, and then fixed: the tip is
read inside the append, holding a handle that excludes other writers, so the pair is one moment.

**What the current ledger actually looks like, measured rather than assumed** (2026-10-13): 33
records, 23 chained and 10 unchained as designed, and the chain breaks nowhere. **17 of the 33 name
paths that no longer exist.** That is not tampering; it is what signing in a scratch directory
produces, and it leaves half the ledger asserting that something was signed about a file nobody can
check any more. Those records are deliberately **not** pruned, because the chain is the value and
pruning is what spends it. The repair is forward-looking and already in place: stage under
`build-artifacts/signed/<repo>/<tag>/` and sign there, which is what `sign-github-release.ps1` does
and what `check-staged-against-ledger.py` exists to compare against.

**One record was removed once, and this is the note that keeps it from being a disappearance.** The
`test.cab` CAB round-trip check (`note: "CAB round trip test (throwaway)"`, 2026-10-12T11:25:19) was
taken out on purpose; its file was already gone. The safety copy made before that removal,
`smyt-signings.ndjson.bak-before-throwaway-removal`, held one record the ledger does not and lacked
four the ledger has, so it was not a spare copy of anything — its only unique line was the throwaway
it had been made to protect. It has been deleted, and what it held is written here instead.

The reason that paragraph exists at all is the limit worth knowing about this file: **removing a
record and recomputing the chain leaves no trace in the chain.** `prev` catches an edit that nobody
repaired. It cannot catch a repair, and it is not meant to — which is why a removal has to be a
decision somebody can point at, in writing, rather than an absence somebody notices later.

A signature without a record of what it covered is half a claim. This is the other half.

## Checking, not assuming

`-Check` compares the ledger against the disk and reports four outcomes, which are four different
things rather than one:

| verdict | meaning |
|---|---|
| unchanged | the bytes on disk are the bytes that were signed |
| superseded | the path holds a later build this ledger also signed — routine, and named |
| changed | the bytes match no signing on record; this is the one worth reading |
| now unsigned | the bytes on disk are the pre-signing bytes; the signature is gone |
| gone | the recorded path no longer exists |

`superseded` exists because the first version of this reported a rebuilt-and-resigned path and a path
touched by something unknown the same way, and six alarming lines were drowning out the one that
matters. The summary now separates them, so the number to read is the second one:

```
10 record(s): 4 unchanged, 6 superseded by a later signing of the same path,
              0 changed by something this ledger has no record of, 0 now unsigned, 0 gone
```

This is the question the ledger exists to answer, and until now nothing asked it. It has already
earned its place: a signed build was silently replaced by an unsigned rebuild, and one path carried
three different signed builds inside twelve minutes. None of that was visible before.

`-Status` prints the certificate, the four stores, the verdict, the ACLs on the key material, and
the ledger's shape. It exists because this README used to state the machine's trust state as a
sentence, and the sentence went stale — the root trust it described had been removed, and every
signature on this machine was reporting `UnknownError`. A sentence cannot go stale if a command
prints it.

## Running the toolchain against itself

```powershell
.\smyt-selftest.ps1                            # 21 checks; nothing outside cache\tmp is touched
.\smyt-selftest.ps1 -IncludeCertificateTest    # also -NewCertificate, with a throwaway subject
```

Every check in it exists because that thing was wrong at least once and nothing noticed. The ledger
was read with the wrong encoding and lost Chinese records. signtool was chosen by sorting full
paths, so an x86 build won over the x64 one. The chain's tip was read outside the append, so two
concurrent signings forged a fork that read as an edit. `-CheckFile` answered a question about a
never-signed file with a friendly note and a zero exit code when the ledger happened to be empty.
`-NewCertificate` could not run at all, because `if (Test-Path $a -or Test-Path $b)` parses as one
command with `-LiteralPath` bound twice. And `-SigningDir` stopped at the edge of the release
script, and again at the edge of the wrapper above it, so a rehearsal against a copied certificate
still appended to the real ledger — which is how a test build got into the real record. That last
one is now a check of its own: the self-test signs through the release wrapper with a scratch ledger
and fails if the real one grows.

It runs entirely in a scratch directory — no real ledger, no trust store, no build output — and it
also proves the chain notices a real edit, because a tamper detector that never fires is decoration.
The unsigned sample it signs is made by clearing the PE's certificate-table entry and truncating the
file there, which is what an embedded signature physically is; `signtool remove` is not used because
it refuses some Microsoft binaries outright and, on a catalog-signed one, exits zero having removed
nothing.

## Things that will bite again if written down nowhere

**A native command's stderr is an ErrorRecord as soon as you redirect it.** Under Windows PowerShell,
`2>&1` and `2>$null` alike turn each line of a native command's stderr into an error record, and every
script here runs with `$ErrorActionPreference = 'Stop'` -- so the redirect itself throws, before the
exit code can be read. The symptom is a check of a *failure* path failing for the failure it was
watching for: the sealing check added on 2026-10-13 passed under 7 and failed under 5.1 with node's
own `cannot open ... unable to authenticate data` as the message. Lower the preference around the one
call that is expected to fail:

```powershell
$quiet = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try { & node $seal open $tampered 2>$null; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $quiet }
if ($code -eq 0) { throw 'it opened instead of being refused' }
```

The general form: **`$LASTEXITCODE` is unreachable in 5.1 for any redirected command whose stderr is
non-empty**, and a failure-path check is exactly where that bites.

**`ConvertFrom-Json` infers types, and the inference changed at PowerShell 6.0.** From 6.0 onward an
ISO-8601 string becomes a `[DateTime]`; 5.1 leaves it a string. The ledger's `t` is
`2026-10-05T08:43:25.3340146Z`, so `Read-SmytLedger` handed back two different types depending on
which edition read it, and the seven places in `smyt-sign.ps1` that format a date with
`.Substring(0, 19)` worked on 5.1 and threw on 7 -- at the first of the seven, so the other six never
ran.

The tempting fix is to convert the value afterwards, and it was measured before being rejected:
`[string]` on a `DateTime` **reformats it with the machine's culture**, so that timestamp comes back
as `10/05/2026 08:43:25`. The sub-second part and the `Z` are gone, month and day swap on a machine
whose culture orders them the other way, and the consumers would stop throwing and start printing a
date the ledger does not contain -- silently, which is worse than throwing.

The parse itself has to not infer. `ConvertFrom-Json -DateKind String` says so and was added in
PowerShell 7.5; on an edition between 6.0 and 7.4, which has the inference and not the switch,
`$value.ToString('o')` is the one formatting that reproduces the text exactly, and it is right
because the ledger writes `Z` and the parsed kind is then `Utc`. `Read-SmytLedger` now does both,
for **every** date-valued field rather than for `t`, because the next field added would otherwise
reintroduce this. The rule underneath it: **a reader's contract is to hand back the fields the file
holds, and a JSON library's version behaviour is not allowed to change that.** The self-test holds it
to that with a file it writes itself, and those four assertions were run against the old parse first,
where all four fail.

**A PowerShell script containing non-ASCII must keep its byte order mark.** Windows PowerShell reads
a `.ps1` with no BOM using the machine's ANSI code page, so a Chinese character is misdecoded before
the parser sees it — and if the last character's tail byte pairs with a closing quote, the file does
not parse at all. That is the ledger's failure one level up, and the first draft of the self-test
was unparseable for exactly this reason. The self-test now builds its Chinese test string from code
points and stays pure ASCII, so no editor or rewrite can break it by dropping a mark it does not
know to keep. Prefer that to remembering which files carry a BOM.

**The environment.** Windows PowerShell resolves a module by walking `PSModulePath` in order and
taking the first directory that holds it. A PowerShell 7 session exports its own module directories
at the front of that variable, and any 5.1 process started from there inherits the order — so 5.1
tries to load 7's binary modules, cannot, and `Get-FileHash`, `Get-AuthenticodeSignature`,
`ConvertTo-SecureString` and `Get-Acl` stop existing in that session. Every script here repairs the
order before doing anything, and hashing is done in .NET so the ledger can always be read. If you
see "Get-FileHash is not recognized" anywhere else, that is this.

**The toolchain.** The PyInstaller interpreter lives at
`E:\DaShaoHuo\toolchains\pyi\Scripts\python.exe`, and it used to live in `cache\tmp`, which the disk
policy tells whoever cleans this machine to empty — and it had been emptied, so the build path was
broken with nothing to show for it. A toolchain is not a temporary file. To recreate it:

```
python -m venv E:\DaShaoHuo\toolchains\pyi
E:\DaShaoHuo\toolchains\pyi\Scripts\python.exe -m pip install pyinstaller
```

PyInstaller warns that running as administrator is neither necessary nor sensible, and says version
7.0 will refuse to do it. That warning is worth heeding before it becomes an error: build from a
normal account, and let signing be the elevated step.

**The key material's ACL.** The password file was hardened when it was created and the private key
beside it was not, so for a while the key was readable *and writable* by every authenticated user
while the password was locked to one account. The pfx is the file that matters; `-Protect` fixes
both, the ledger and the directory, and `-Status` reports what the ACLs actually say rather than
what they were meant to say.

**Sealed files, and why the password is not a `.txt` any more.** A file ending in `.sealed` is an
AES-256-GCM container with the magic `VSEP1` — the same container volcano-separator writes, so one
format serves both rather than two. The key lives in `sealed.key`, protected with DPAPI for this
machine, which is what makes the container readable by this ecosystem's tooling and by nothing else:
a text reader, a grep, or an editor opening the file by extension gets ciphertext.

    node seal.mjs seal <file> [out]     encrypt; default output replaces the extension with .sealed
    node seal.mjs seal - <out>          encrypt from standard input, so nothing plaintext hits disk
    node seal.mjs open <file> [out]     decrypt to a file, or to standard output without one
    node seal.mjs info <file>           what the container says about itself, without the key

The container is verified by round-trip BEFORE it is written — decrypted again in memory and compared
— because a container nobody can open is worse than no container, and the cost is one comparison.

The pfx password was converted to this form on 2026-10-13 and the plaintext file was deleted. Reading
it back is one command:

    node seal.mjs open pfx-password.sealed

**What sealing does not do, and the consequence worth stating.** The key is bound to THIS machine, so
the sealed password cannot be opened anywhere else — and the pfx exists precisely for disaster
recovery on another machine. Keep the password in a password manager (or on paper) as well: the sealed
file protects what is on this disk, not what happens if the disk is gone. Sealing also does not shred,
and DPAPI scope here is LocalMachine, so any account that can read the key blob can unseal it.
