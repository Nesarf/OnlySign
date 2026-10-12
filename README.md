# OnlySign

Sign local build artifacts, and be able to say later what was signed.

Most people who need to sign a binary do not own a code signing certificate, have never made one,
and do not have the Windows SDK installed. OnlySign starts from that position: it can make a
certificate, find the artifacts in a project, sign them, and keep a record that an edit cannot
quietly change.

## The two facts this is built on

**It needs no SDK.** `Set-AuthenticodeSignature` is part of Windows PowerShell, which is on every
Windows, and it signs a PE image and attaches an RFC 3161 timestamp just as well as the SDK's
`signtool`. Verified here, not assumed. That single fact is the difference between a tool for people
who already had the toolchain and a tool for everyone.

**The engine is separate from the window.** The window is the easy half. What is hard -- refusing to
sign twice, refusing to leave a signature that expires with the certificate, pinning the signer, and
keeping a record that shows when it has been edited -- lives in `onlysign/engine/`, where it can be
tested without anyone clicking. The window, when it arrives, only draws what the engine already
decided.

## Using it

The window, once it is built:

```
dist\OnlySign.exe                 the window
dist\OnlySign.exe scan <project>  the command line, from the same binary
```

From a checkout, without building anything:

```powershell
python -m onlysign.gui                          # the window
python OnlySign.py                              # the same window, through the packaged entry point
python -m onlysign selftest                     # run the engine against itself: 37 checks
python -m onlysign selftest --keep              # leave the scratch directory behind to look at
python tools/gui_smoke.py                       # drive the window the way a person would: 6 checks

python -m onlysign scan  <project>              # propose artifacts, with the reason for each
python -m onlysign certs                        # what could sign
python -m onlysign certs --create "CN=Your Name" --out .\keys
python -m onlysign sign  <file>... --cert <name> --dry-run
python -m onlysign sign  --repo <project> --cert <name> --ledger .onlysign\signings.ndjson
python -m onlysign check --ledger .onlysign\signings.ndjson
python -m onlysign trust --cert <name> [--install user-root]
```

`--cert` takes a full thumbprint, an unambiguous prefix of one, or part of a subject; an ambiguous
answer is an error listing the candidates rather than a guess. Exit codes are meant to be used: 0
when everything asked for happened, 1 when something did not, 2 for a usage error -- so `check` in
a pipeline fails when a signed artifact has stopped being the one that was signed.

There is no dependency and nothing to pip install.

## The window, and what it does not do

The window decides nothing. Which artifacts exist, which certificate can sign, whether a file is
already signed, whether the signature landed, whether a timestamp was obtained -- every one of those
questions was answered before the window was written, by functions the command line calls too. What
is in `onlysign/gui.py` is layout, plus a worker thread so that a scan or a signing run does not
freeze it.

```
Project directory [_______________] [Browse]      the repository
Artifact directory[_______________] [Browse]      given one, the scan takes it at its word
[Scan]          → a list of what was found, each line saying why

Certificate     [ a code signing certificate with a private key, showing expiry ]
Signing           note, where signed copies go, where the record goes, timestamp authorities
Trust           ○ none  ○ user: publishers  ○ user: root  ○ machine: both
[Dry run] [Execute signing] [Check the ledger]
```

Signing and installing trust are two groups rather than one list of options on purpose, and that is
the point most easily got wrong: a trust store decides what **this machine** accepts, and it is not
a property of the signature. The two that matter are not equal either -- the root store is the trust
anchor and decides whether anything verifies, while the publisher store alone changes no verdict
anywhere. The window says so on the radio buttons themselves.

`Execute signing` asks once before it does anything, because a signature cannot be taken back off a
file. `Dry run` never writes.

The window sizes itself to the screen it opens on, positions itself inside that screen, and scrolls
its content if the content does not fit. None of that was true of the first version: on a
1536x864 screen the content wanted 1086 pixels, so the trust choices, the buttons and the result
were off the bottom edge -- and setting only a size, not a position, left the window 40 pixels below
the bottom of the screen as well. The buttons and the result are now pinned outside the scrolling
area, because a set-once choice can be scrolled to and the two things a person reaches for after
every action cannot be one scroll away from where they are looking.

`tools/gui_smoke.py` exists so this claim is tested rather than asserted: it opens the real window,
fills in the real fields, presses the real buttons, and then reads the ledger the window wrote.

## Building the executable

```powershell
python tools/build.py                       # the window, no console
python tools/build.py --console             # the same, but with a console -- the one that can be checked
python tools/build.py --icon path\to.ico    # a different icon than the one that ships
```

One file, about 13 MB, no runtime to install. `--python` points at the interpreter that has
PyInstaller, which is a dependency of *building* the tool and not of using it. The work directory
goes to the system temp area, because a build leaves a great deal behind that nobody wants in a
source tree. The build uses `mark/onlysign.ico`; `--no-icon` leaves it off.

The packaged binary has two doors: started with no arguments it opens the window, started with a
command (`scan`, `certs`, `sign`, `check`, `trust`) it behaves like the command line. That is what
makes it testable -- an executable that only opens a window is one that cannot be checked from a
script. Note that a one-file build starts a bootloader which then starts the real process, so the
process id you get from launching it is not the one that owns the window.

## Finding the artifacts

A scanner that returns a list of paths is not much use on its own -- the person reading it has no way
to judge it. Every candidate here carries the reason it was proposed, and a path that two layers
agree about shows both reasons:

```
app.exe  [a PE image, 3334144 bytes, unsigned]
    E:\project\dist\app.exe
    found: it is in a directory named 'dist'
    found: .github\workflows\release.yml says the output is dist/*.exe

note: installer.iss says the output is 'Output\DemoSetup', and there is nothing signable there
```

Four layers, each adding candidates rather than replacing them: the directory you named; directories
named like an output directory; build files that declare where their output goes (Inno, NSIS, WiX,
PyInstaller, electron-builder, Cargo, MSBuild, CI workflows -- including globs, because a workflow
says `dist/*.exe` far more often than it names a file); and the local object library, which already
knows paths this machine has seen. A declared output with nothing in it is reported as exactly that,
because a thin list is usually a project that has not been built rather than one with no artifacts.

## The rules the engine enforces

These are not preferences; each one is the answer to something that went wrong.

* **Never sign a file twice.** Authenticode appends a certificate table instead of replacing one, so
  a second pass would leave the record of that signing describing the *previous signature's output*
  -- the one field that says what the build was.
* **A signature with no timestamp is treated as a failure.** It stops verifying when the certificate
  does. Several authorities are tried in order; if none answers, the attempt is undone.
* **The engine undoes what a failure leaves behind.** `signtool` restores the file when the
  timestamp cannot be reached. `Set-AuthenticodeSignature` does **not**: it appends a complete
  signature and leaves it there. So the engine puts back the length, the PE checksum and the
  certificate-table entry itself, and then proves it by comparing the file's hash with the hash from
  before.
* **A verdict and a fact are different questions.** `Get-AuthenticodeSignature` consults the
  machine's security catalogs, so a Microsoft binary whose own signature was removed still answers
  "signed by Microsoft" -- with a Microsoft timestamp. Asking it whether *our* signature landed would
  get an answer about somebody else's. The engine asks the file instead, and keeps the two answers
  apart.
* **The signer is pinned by thumbprint**, and the key is taken from the certificate store, so no
  password ever appears on a command line where every process on the machine can read it.
* **A private key is not left open to everyone.** A certificate made here has its key file taken out
  from under inherited permissions, down to the owning account, the administrators and the system.
  On the machine this was written on, the password file had been locked down and the key beside it
  had not: it was readable *and writable* by every authenticated user.

## The ledger

Every signing appends one line of JSON to a ledger: the file, its size, its SHA-256 **as signed**
and **before signing**, the signer, the thumbprint, whether a timestamp was obtained, which
authority provided it, and the hash of the previous line.

The format is not this project's invention -- an existing signing toolchain already writes it, and
two implementations writing one file have to write the same bytes. What matters about it:

* it is **UTF-8 with no byte order mark**, read and written as such, because reading it with the
  machine's ANSI code page turns a Chinese note into mojibake and can make a whole record unparseable;
* the `prev` field makes an edit to the ledger a visible break rather than a silent one;
* the tip is read and the line written **inside one lock**, because when those are two operations two
  signings that overlap name the same parent and the chain reports a fork -- which reads as "someone
  edited the ledger" on a file nobody touched.

## Asking whether it is still true

`onlysign check` compares the ledger against the disk and keeps the answers apart, because they are
not the same kind of news:

| verdict | what it means |
|---|---|
| unchanged | the bytes on disk are the bytes that were signed |
| superseded | the path holds a later build *this ledger also signed* -- routine, and named |
| changed | the bytes match no signing on record. This is the one worth reading |
| now unsigned | the file carries no signature of its own any more |
| gone | the recorded path does not exist -- which is what a signed-in-a-temp-directory record becomes |

An earlier version reported the routine case and the alarming one identically, and six alarming
lines buried the one that mattered. Only `changed` and `now unsigned` make the command exit non-zero,
so a pipeline notices when a signed artifact has stopped being the one that was signed.

## How this talks to Windows

Two traps cost a session on the machine this was written on, and both are fixed structurally rather
than remembered, in `onlysign/engine/ps.py`:

* **A script that has to be decoded can be misdecoded.** Windows PowerShell reads a `.ps1` with no
  byte order mark using the machine's ANSI code page; a script containing non-ASCII text can be
  misread *before it runs*. Scripts here are never written to disk: they travel as base64 UTF-16
  (`-EncodedCommand`), so a path with a Chinese character in it is not merely tolerated -- the
  ambiguity does not exist.
* **A module that cannot be found is not an error you get to see.** A PowerShell 7 session puts its
  own module directories at the front of `PSModulePath`, so a 5.1 child started from there fails to
  load its own `Microsoft.PowerShell.Security` and `Set-AuthenticodeSignature` simply ceases to
  exist. The child is handed a clean module path.

## Layout

```
OnlySign.py                  the entry point that gets packaged; one binary, two doors
onlysign/engine/ps.py        the only place that talks to Windows
onlysign/engine/ledger.py    the record, and the lock that keeps its chain honest
onlysign/engine/pe.py        what a file is; what a signature physically is; how to undo one
onlysign/engine/certs.py     what can sign, and how one comes to exist
onlysign/engine/signer.py    putting a signature on, checking the right one landed
onlysign/engine/discover.py  finding the artifacts, and saying how each one was found
onlysign/engine/audit.py     asking the ledger whether it is still true
onlysign/engine/trust.py     the two stores, and the difference between them
onlysign/engine/workflow.py  the order of operations, which is where the rules live
onlysign/gui.py              the window; layout and a worker thread, nothing else
onlysign/cli.py              the engine with a keyboard instead of a window
onlysign/selftest.py         37 checks of the engine, in a scratch directory
tools/build.py               building the one-file executable
tools/gui_smoke.py           6 checks that drive the window itself
tools/cfb-probe.py           what a compound file's header says, against what the reader returned
dist/                        built executables (not committed)
```

## Status

Built and checked at every level:

| what | how it is checked |
|---|---|
| the engine | `python -m onlysign selftest` -- 37 checks, in a scratch directory |
| the window | `python tools/gui_smoke.py` -- 6 checks that open it and press its buttons |
| both PowerShell editions | the same 37 checks under Windows PowerShell and under PowerShell 7 |
| the executable | about 13 MB, one file: lists certificates, answers `scan --help`, opens its window |
| reading a container | `python tools/cfb-probe.py <dir>` -- every compound file in it, against its own header |

The last two rows are verified rather than assumed. The packaged build was run and its window
opens, because tcl/tk having been bundled correctly is not something a build log tells you. The
checks run under both editions because .NET methods and module paths are not the same in both --
the first version of this tool named one edition's paths as constants.

Nothing is known to be missing in what it reads. Both package formats it was thought to be unable
to read turned out to be readable, and one of them for a simpler reason than expected:

* **MSI** keeps its signature as one stream among many inside a compound file, so that one did need a
  reader -- `onlysign/engine/container.py`, checked against packages signed here.
* **CAB** does not: measured on a cabinet signed with this tool, `cbCabinet` ends at byte 132 and the
  PKCS#7 begins exactly there, appended the way a PE's certificate table is. The .NET call the engine
  already used had been reading it all along, and a reader written for it was deleted after the
  measurement showed it was looking in `abReserve`, which holds something else.

What the compound-file reader got wrong is worth recording, because it was wrong in a way that a
passing test suite could not see. Sectors were found at `512 + index * sector_size`. Sector 0 begins
after the header, so the offset is `(index + 1) * sector_size` -- and those two expressions are the
same arithmetic whenever a sector is 512 bytes. Every file it was tried on was one, including the
hand-built fixture in the self-test. On a 4096-byte-sector package the offset landed 3584 bytes early,
inside the allocation table rather than at the directory, so the reader followed a table describing
something else, walked a chain that was never the directory's, and parsed the sectors it reached as
directory entries. A 1.2 MB package returned 64 MB of entries -- bounded by a byte cap, so it did not
die, and the real entries were among them, so lookups still mostly worked. Measured afterwards across
931 compound files in the Windows installer cache: 371 of the 382 that carry a signature use 4096-byte
sectors, which is to say the embedded signature of nearly every one of them was being missed and the
question was being handed to Windows instead -- and a machine's answer comes from its security
catalogs, which is the ambiguity the reader exists to remove. Two further changes came out of it: a
chain that revisits a sector is now refused rather than walked to a cap, and the directory walk is
bounded by the sector count the header states instead of by a byte ceiling. The self-test builds its
fixture at both sector sizes, and it was confirmed to fail against the old arithmetic before being
kept -- a regression test that has not been seen to fail is a guess.

Reading an MSI's signature also needed `Add-Type -AssemblyName System.Security`. Windows PowerShell
does not resolve `SignedCms` without it, so on that edition the whole path failed with "type not
found" while working under PowerShell 7 -- a difference between the two editions of exactly the kind
the both-editions row above exists to catch, and it had not been caught because the failure came back
as "this package carries no signature" rather than as an error.

Attribution on an MSI was measured rather than assumed, and the answer is that the signed carrier is
already there. A package's certificate subject is inside what its signature covers, so `O=` in the
subject is a claim the signature vouches for -- stronger than any field the installer's own tables
hold, and it needs no code. The other candidate is the summary information stream, which is what
Explorer's Details pane shows; it does exist (`\u0005SummaryInformation`) and the platform's own API
writes it, but two things were measured about it. It has no spare room -- the declared section size
exactly fills the stream on every package looked at -- so writing to it is a container rewrite, not a
patch. And the string it stores went through the machine's ANSI code page: on a code page 1252 machine
`(c)` stores as `A9`, on the 936 machine this was measured on it cannot be encoded at all and came
back as `7F`, while `\u4e2d` round-tripped untouched. So whether a `(c)` survives in that field is a
property of the machine, not of this tool, which is why the mark's own ASCII form is the one to place
there -- and why placing it belongs before signing, like every other mark.

A terminal cannot be tested by a script, so `tools/terminal-probe.ps1` exists for a person to run in
each one. What the gate's output depends on is a short list -- whether stdout is a console, what it
is encoded as, how wide the window is -- and nothing in the tool branches on which terminal it is in.
