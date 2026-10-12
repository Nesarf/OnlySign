"""Driving a terminal, so that what a person would see can be read back by a script.

Two attempts at this failed before it worked, and both failures are designed out here rather than
remembered:

* A GUI started with the shell's `&` keeps the tool's pipes open, so the foreground work finishes and
  the caller still waits. Everything long-lived here is started detached, and every command that
  talks to a terminal is given a timeout -- a timeout is a reportable error, and a hang is not.
* Waiting a fixed number of seconds for a terminal to be ready is a guess that is wrong in both
  directions. Readiness is a file appearing on disk, so it is polled for, with a deadline.

What each terminal allows is a fact about that terminal, not about this file. Where one cannot be
driven, the driver says so in `LIMITS` instead of pretending, because a driver that silently does
nothing is worse than one that is absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time

DEFAULT_TIMEOUT = 25.0


class TerminalError(RuntimeError):
    """Raised when a terminal cannot be driven, with what was tried and what happened."""


def _run(argv: list[str], *, timeout: float = DEFAULT_TIMEOUT) -> str:
    """Run a short command and return its output. A timeout is an error, never a wait."""
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise TerminalError(f"{os.path.basename(argv[0])} did not answer within {timeout:g}s") from None
    except OSError as exc:
        raise TerminalError(f"could not run {argv[0]}: {exc}") from None
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).decode("utf-8", "replace").strip()[:200]
        raise TerminalError(f"{os.path.basename(argv[0])} exited {proc.returncode}: {detail}")
    return proc.stdout.decode("utf-8", "replace")


class Terminal:
    """One session in one terminal: something was started, and it can be read and typed into."""

    name = "terminal"

    def read(self) -> str:
        raise NotImplementedError

    def send(self, text: str) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class WezTerm(Terminal):
    """WezTerm, driven through its own CLI.

    The CLI talks to a mux; on Windows that mux is the GUI process, so the GUI has to be running
    before anything else will answer. `wezterm-mux-server --daemonize` looks like the headless answer
    and is not one: the flag means fork, and there is nowhere to fork to on Windows, so it sits there.
    """

    name = "wezterm"

    def __init__(self, exe: str, state_dir: str, workspace: str = "default"):
        self.exe = exe
        self.state_dir = state_dir
        self.workspace = workspace
        self.pane = ""

    # --- readiness ------------------------------------------------------------ #

    def _socket_present(self) -> bool:
        try:
            return any(name.startswith(("gui-sock", "sock")) for name in os.listdir(self.state_dir))
        except OSError:
            return False

    def ensure_running(self, *, deadline: float = 40.0, start: bool = True) -> None:
        """Wait for the mux to exist, starting the GUI once if it does not."""
        if self._socket_present() and self._answers():
            return
        if start:
            # Detached on purpose: a GUI attached to this process's pipes is what hung the first
            # attempt, and the harness's own job handling is not available to a library.
            subprocess.Popen([self.exe, "start", "--always-new-process"],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             stdin=subprocess.DEVNULL, close_fds=True,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        waited = 0.0
        while waited < deadline:
            time.sleep(1.0)
            waited += 1.0
            if self._socket_present() and self._answers():
                return
        raise TerminalError(f"no mux appeared within {deadline:g}s (state dir {self.state_dir})")

    def _answers(self) -> bool:
        try:
            _run([self.exe, "cli", "list"], timeout=6.0)
            return True
        except TerminalError:
            return False

    # --- the session ---------------------------------------------------------- #

    def open(self, argv: list[str], *, cwd: str = "") -> str:
        """Start a command in a new pane and return its pane id."""
        self.ensure_running()
        command = [self.exe, "cli", "spawn", "--pane-id", "0"]
        if cwd:
            command += ["--cwd", cwd]
        command += argv
        out = _run(command)
        # The pane id is the last line: the CLI logs warnings before it.
        for line in reversed(out.splitlines()):
            line = line.strip()
            if line.isdigit():
                self.pane = line
                return line
        raise TerminalError(f"no pane id in the answer: {out.strip()[:200]}")

    def read(self) -> str:
        if not self.pane:
            raise TerminalError("nothing has been started yet")
        out = _run([self.exe, "cli", "get-text", "--pane-id", self.pane])
        return "\n".join(line.rstrip() for line in out.splitlines())

    def send(self, text: str) -> None:
        if not self.pane:
            raise TerminalError("nothing has been started yet")
        # --no-paste types the text rather than pasting it, which is what a person does and what a
        # read of the console's input sees. A carriage return has to be sent on its own: a line feed
        # puts the character on screen and does not end the line.
        _run([self.exe, "cli", "send-text", "--pane-id", self.pane, "--no-paste", text])

    def close(self) -> None:
        if self.pane:
            try:
                _run([self.exe, "cli", "kill-pane", "--pane-id", self.pane], timeout=10.0)
            except TerminalError:
                pass
            self.pane = ""


# What each terminal allows, and why, so that nobody has to discover it twice. `driver` is None
# where no way was found -- that is an answer, not a gap to be filled by guessing.
LIMITS = {
    "wezterm": {
        "driver": WezTerm,
        "read": True,
        "write": True,
        "how": "the CLI's spawn / get-text / send-text, against the mux the GUI provides",
    },
    "tabby": {
        "driver": None,
        "read": False,
        "write": False,
        "how": "Electron. Nothing in the shipped CLI reads a pane or types into one, so it would "
               "have to go through the remote debugging port and the renderer's own DOM, which is "
               "a different piece of work with a different failure surface.",
    },
    "windterm": {
        "driver": None,
        "read": False,
        "write": False,
        "how": "No scripting surface, and the terminal is drawn rather than built from controls, so "
               "there is nothing for UI Automation to read. Typing into it would be possible by "
               "sending window messages; reading it back would not.",
    },
    "bash": {
        "driver": None,
        "read": True,
        "write": True,
        "how": "Already covered without a driver: the gate is run the same way a person runs it and "
               "the output is the process's own stdout.",
    },
}


def find(name: str) -> tuple[str, str]:
    """(executable, state directory) for a terminal, from where it is usually installed."""
    if name == "wezterm":
        exe = os.environ.get("WEZTERM_EXECUTABLE") or shutil.which("wezterm") or \
            r"D:\DaShaoHuo\apps\WezTerm\wezterm.exe"
        state = os.environ.get("WEZTERM_STATE_DIR") or os.path.join(
            os.environ.get("USERPROFILE", ""), ".local", "share", "wezterm")
        return exe, state
    if name == "tabby":
        return shutil.which("tabby") or r"C:\Program Files\Tabby\Tabby.exe", ""
    if name == "windterm":
        return shutil.which("WindTerm") or r"D:\DaShaoHuo\apps\WindTerm\WindTerm.exe", ""
    return "", ""
