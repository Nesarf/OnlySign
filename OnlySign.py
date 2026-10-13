"""The entry point that gets packaged into one executable.

One binary, two doors. Started with no arguments it opens the window; started with a command it
behaves like the command line, which is what makes the packaged build verifiable -- a `.exe` that
opens a window and can be checked in no other way is an executable nobody can test.
"""

from __future__ import annotations

import sys

from onlysign.cli import command_names
from onlysign.cli import main as command_line
from onlysign.gui import main as window

# Read from the command line's own parser rather than restated here. The literal that used to be on
# this line fell one behind the first time a verb was added: `mark` worked under `python -m onlysign`
# and was handed to the window by this file, so the built executable did not have it. A second copy
# of a list is a second place for it to be wrong.
COMMANDS = set(command_names())


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] in COMMANDS:
        return command_line(arguments)
    return window(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
