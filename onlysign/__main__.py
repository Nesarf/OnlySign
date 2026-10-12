"""``python -m onlysign`` -- the command line, so the package is runnable without installing it."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
