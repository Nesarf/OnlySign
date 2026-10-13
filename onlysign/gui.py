"""The window.

It decides nothing. Every question -- which artifacts, which certificate, whether the file is
already signed, whether the signature landed, whether a timestamp was obtained -- was answered
before this file was written, by functions the command line calls too. What is here is layout, and a
thread so that a scan or a signing run does not freeze the window while it works.

Two things about tkinter shape the code: widget calls are only safe from the thread that created
them, so work happens in a worker and the result is handed back through a queue the main thread
polls; and a signing run can take a minute, so the buttons are disabled while one is in flight
rather than left to be clicked twice.

Three things about language shape it too:

* **One language at a time.** The window speaks Chinese, English or Japanese, and shows only that
  language's words. Nothing is bilingual side by side; the menu switches, and every word changes.
* **Two fonts inside every language.** Chinese in 宋体 with Latin in Times New Roman; Japanese in
  明朝体 with Latin in ゴシック体. Times New Roman has no CJK glyphs at all -- rendered in it, 项目目录
  comes out as four empty boxes -- so a string that mentions another script is split into runs and
  each run is drawn in its own font. `split_scripts` is that, and it is why labels are frames.
* **Switching rebuilds.** Every word lives in one table, and changing language re-creates the window
  with a different reading of that table. Re-pointing each widget by hand would be a second place for
  the words to live, and the second place is the one that goes stale.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from . import i18n, mark
from .engine import (audit, bootmark, certs, discover, pe, signer, trust, workflow)

WINDOW_TITLE = "OnlySign"
SETTINGS_NAME = "gui.json"

# The pages the window offers: the string key that names each one and the name it is known by inside
# the code. One table rather than two lists, because two lists of the same length are two lists that
# drift -- and the drift would be a page either named by a key nothing loads or built under a name
# nothing selects. `--tabs` compares against this, so a page written and never added is a shortfall
# rather than silence.
TABS = (("tab.artifacts", "artifacts"), ("tab.signing", "signing"),
        ("tab.trust", "trust"), ("tab.mark", "mark"))
TAB_KEYS = tuple(key for key, _ in TABS)


def make_dpi_aware() -> bool:
    """Tell Windows this process draws its own pixels, before any window exists.

    Without this, a process that has not declared DPI awareness is drawn into a smaller virtual
    desktop and then **stretched by the scale factor** -- 125% on the machine this was written on --
    which is what makes every label look soft. The giveaway is measurable rather than aesthetic: Tk
    reported a 1536x864 desktop at 96 dpi while the display was 1920x1080 at 120, so every
    coordinate this program computed and every coordinate Windows reported were 1.25 apart.

    Not the per-monitor mode: Tk does not rebuild its fonts when a window is dragged to a display
    at another scale, so per-monitor awareness trades one blur for a different one. System awareness
    is the setting that makes text sharp where the window opens and then behaves.
    """
    if os.name != "nt":
        return False
    try:
        import ctypes
    except ImportError:
        return False
    attempts = (("shcore", "SetProcessDpiAwareness", 1),
                ("user32", "SetProcessDPIAware", None))
    for library, name, argument in attempts:
        try:
            module = getattr(ctypes.windll, library, None)
            function = getattr(module, name, None) if module is not None else None
            if function is None:
                continue
            function() if argument is None else function(argument)
            return True
        except (AttributeError, OSError):
            continue
    return False


# At import, because the alternative is remembering to call it, and the failure mode of forgetting
# is a window nobody can read. Importing this module means a window is about to be made.
make_dpi_aware()


def use_bundled_fonts() -> list[str]:
    """Make the fonts that travel with the tool available to this process, and say which loaded.

    `AddFontResourceExW` with FR_PRIVATE registers a font file for this process only, so nothing is
    installed on the machine and nothing is left behind when it exits. A console cannot choose a font
    for one line -- that is why the gate's banner is letter-spacing and a frame -- but a window can,
    and this is where the font that came with the tool becomes usable.

    The fonts are data, so they travel beside the code; a missing one costs the typeface and never
    the window.
    """
    if os.name != "nt":
        return []
    loaded: list[str] = []
    roots = [os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]
    bundled = getattr(sys, "_MEIPASS", "")
    if bundled:
        roots.append(bundled)
    if getattr(sys, "frozen", False):
        roots.append(os.path.dirname(sys.executable))
    try:
        import ctypes
        add = ctypes.windll.gdi32.AddFontResourceExW
    except (AttributeError, OSError, ImportError):
        return loaded
    FR_PRIVATE = 0x10
    for root in roots:
        folder = os.path.join(root, "mark", "fonts")
        if not os.path.isdir(folder):
            continue
        for name in sorted(os.listdir(folder)):
            if not name.lower().endswith((".ttf", ".otf")):
                continue
            path = os.path.join(folder, name)
            if add(ctypes.c_wchar_p(path), FR_PRIVATE, 0):
                loaded.append(name)
    return loaded


FONTS_LOADED = use_bundled_fonts()

# The face the tool's own wordmark is set in, when it came along. Trajan-style capitals are what the
# line this echoes is set in; a console cannot be told to use it, a window can.
WORDMARK_FONT = "Cinzel"


def ascii_banner() -> str:
    """The same words the gate answers a yes with, taken from the same table."""
    from . import phrases
    return phrases.table(i18n.DEFAULT_LANGUAGE)["bonfire"]


def wordmark_font(size: int) -> tuple[str, int]:
    return (WORDMARK_FONT if any("cinzel" in n.lower() for n in FONTS_LOADED)
            else i18n.FONTS[i18n.DEFAULT_LANGUAGE]["latin"], size)


def split_scripts(text: str) -> list[tuple[str, str]]:
    """Cut a string into runs of one script, so each run can be drawn in its own font.

    ASCII counts as Latin and everything else as Han; that is coarse, and it is the distinction that
    matters here, because the two fonts differ in exactly one way that can be seen: whether a
    character has a glyph at all. Runs are never reordered or dropped, so a string is drawn exactly
    as written -- the split exists to choose a font, not to change a word.
    """
    runs: list[tuple[str, str]] = []
    for character in text:
        script = "latin" if character.isascii() else "han"
        if runs and runs[-1][0] == script:
            runs[-1] = (script, runs[-1][1] + character)
        else:
            runs.append((script, character))
    return runs


def font_of(language: str, script: str) -> tuple[str, int]:
    chosen = i18n.FONTS.get(language, i18n.FONTS[i18n.DEFAULT_LANGUAGE])
    return (chosen[script], i18n.FONT_SIZE)


def dominant_font(language: str, text: str) -> tuple[str, int]:
    """The one font for a widget that can only carry one -- a button, a tab, a tree heading.

    A control cannot hold two fonts, so it gets the font of the script its own words are written in.
    Buttons in this window carry the interface's words, which are one script; a mention inside them
    is drawn in that font's own Latin, which is why the Chinese font is a serif whose Latin is
    Times-shaped rather than a font that would leave boxes.
    """
    has_han = any(not character.isascii() for character in text)
    return font_of(language, "han" if has_han else "latin")


def scripted(parent, text: str, language: str, **label_options) -> ttk.Frame:
    """A label that can hold two fonts: one frame, one label per script run."""
    frame = ttk.Frame(parent)
    for script, chunk in split_scripts(text):
        ttk.Label(frame, text=chunk, font=font_of(language, script), **label_options).pack(side="left")
    return frame


class Settings:
    """What the window remembers between runs. Best-effort: a settings file that cannot be written
    is not a reason to refuse to sign anything."""

    def __init__(self, path: str):
        self.path = path
        self.data: dict = {}
        try:
            with open(path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            if isinstance(loaded, dict):
                self.data = loaded
        except (OSError, ValueError):
            pass

    def get(self, key: str, default: str = "") -> str:
        value = self.data.get(key, default)
        return value if isinstance(value, str) else default

    def put(self, key: str, value: str) -> None:
        self.data[key] = value

    def save(self) -> None:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            with open(self.path, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh, ensure_ascii=False, indent=2)
        except OSError:
            pass


class Window:
    def __init__(self, root: tk.Tk, settings: Settings):
        self.root = root
        self.settings = settings
        self.language = (i18n.normalise(settings.get("language"))
                         or i18n.from_environment() or i18n.DEFAULT_LANGUAGE)
        self.certificates: list[certs.Certificate] = []
        self.candidates: list[discover.Candidate] = []
        self.busy = False
        self.results: queue.Queue = queue.Queue()
        self.widgets: dict[str, object] = {}

        root.title(self.t(i18n_key="app.name"))
        self._build()
        self._fit_to_screen()
        self.refresh_certificates()
        self.root.after(100, self._drain)

    # --- saying things -------------------------------------------------------- #

    def t(self, key: str = "", i18n_key: str = "", **fields) -> str:
        return i18n.translate(i18n_key or key, self.language, **fields)

    def _apply_language(self, language: str) -> None:
        chosen = i18n.normalise(language)
        if not chosen or chosen == self.language:
            return
        self._remember()                        # keep whatever the person typed
        self.language = chosen
        self.settings.put("language", chosen)
        self.settings.save()
        # Rebuild rather than re-point: see the note at the top of this file.
        for child in self.root.winfo_children():
            child.destroy()
        self.root.configure(menu=tk.Menu(self.root))
        self.widgets.clear()
        self.root.title(self.t(i18n_key="app.name"))
        self._build()
        self._fit_to_screen()
        self.refresh_certificates()

    # --- the frame it opens at ------------------------------------------------ #

    def _fit_to_screen(self) -> None:
        """Open at a size that fits the screen it is on, with the content scrolling if it does not."""
        self.root.update_idletasks()
        # The canvas reports its own size, not its content's, so the measurement has to come from the
        # frame inside it -- otherwise the window opens at the minimum and everything is scrolled.
        # The window's own request, which is now the truth: with the pages in a notebook and the
        # buttons outside it, the root's request is the notebook's tallest page plus the row of
        # buttons and the result. Measuring a page directly was wrong -- a page that is not the one
        # showing reports the size it had when it was, which is how the artifact list came out one
        # row tall in Japanese and four rows tall in Chinese.
        wanted_width = self.root.winfo_reqwidth()
        wanted_height = self.root.winfo_reqheight()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        width = min(max(wanted_width, 900), screen_width - 40)
        height = min(max(wanted_height, 480), screen_height - 80)
        # And a position, explicitly. Setting a size and leaving the position to the window manager
        # put this window 40 pixels below the bottom of the screen on the machine it was written on:
        # the size was fine, and the buttons were still invisible.
        left = max(0, (screen_width - width) // 2)
        top = max(0, (screen_height - height) // 2 - 20)
        self.root.geometry(f"{width}x{height}+{left}+{top}")
        self.root.minsize(720, 480)

    def _describe_trust(self) -> None:
        chosen = self.trust_choice.get()
        note = self.widgets.get("trust_note")
        if note is not None:
            note.configure(text=self.t(i18n_key=TRUST_KEYS.get(chosen, "trust.none.why")))

    # --- the menu ------------------------------------------------------------- #

    def _build_menu(self) -> None:
        bar = tk.Menu(self.root)

        file_menu = tk.Menu(bar, tearoff=0)
        file_menu.add_command(label=self.t(i18n_key="menu.scan"), command=self.on_scan)
        file_menu.add_command(label=self.t(i18n_key="menu.dryrun"), command=self.on_dry_run)
        file_menu.add_command(label=self.t(i18n_key="menu.execute"), command=self.on_sign)
        file_menu.add_command(label=self.t(i18n_key="menu.check"), command=self.on_check)
        file_menu.add_separator()
        file_menu.add_command(label=self.t(i18n_key="menu.exit"), command=self.root.destroy)
        bar.add_cascade(label=self.t(i18n_key="menu.file"), menu=file_menu)

        settings_menu = tk.Menu(bar, tearoff=0)
        settings_menu.add_command(label=self.t(i18n_key="field.record"),
                                  command=self._browse_ledger)
        settings_menu.add_command(label=self.t(i18n_key="field.copy_to"),
                                  command=self._browse_output)
        settings_menu.add_command(label=self.t(i18n_key="menu.open_ledger"),
                                  command=self._open_ledger_folder)
        bar.add_cascade(label=self.t(i18n_key="menu.settings"), menu=settings_menu)

        language_menu = tk.Menu(bar, tearoff=0)
        self.language_choice = tk.StringVar(value=self.language)
        for code in i18n.LANGUAGES:
            language_menu.add_radiobutton(
                label=i18n.LANGUAGE_NAMES[code], value=code, variable=self.language_choice,
                command=lambda chosen=code: self._apply_language(chosen))
        bar.add_cascade(label=self.t(i18n_key="menu.language"), menu=language_menu)

        about_menu = tk.Menu(bar, tearoff=0)
        about_menu.add_command(label=self.t(i18n_key="menu.about"), command=self.on_about)
        bar.add_cascade(label=self.t(i18n_key="menu.about"), menu=about_menu)

        self.root.configure(menu=bar)

    def _open_ledger_folder(self) -> None:
        path = self.ledger.get().strip()
        folder = os.path.dirname(os.path.abspath(path)) if path else os.getcwd()
        try:
            os.makedirs(folder, exist_ok=True)
            os.startfile(folder)                             # noqa: S606 - Windows shell open
        except OSError as exc:
            self.say(str(exc), "bad")

    # --- layout --------------------------------------------------------------- #

    def _build(self) -> None:
        self._build_menu()
        pad = {"padx": 6, "pady": 3}

        style = ttk.Style()
        # Two fonts per language, and which one a widget gets depends on what it holds. Entries and
        # list cells hold paths and file names, which can be written in anything, so they get the CJK
        # font; the interface's own words get the font that language asks for.
        data_font = font_of(self.language, "han")
        word_font = font_of(self.language, "latin" if self.language == "en" else "han")
        style.configure(".", font=data_font)
        style.configure("TLabelframe.Label", font=word_font)
        style.configure("Treeview.Heading", font=word_font)
        for name in ("TButton", "TCheckbutton", "TRadiobutton"):
            style.configure(name, font=word_font)

        # The buttons and the result are pinned to the bottom of the window, outside the scrolling
        # area. Set-once choices can be scrolled to; the two things a person reaches for after every
        # action cannot be one scroll away from where they are looking.
        bottom = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        bottom.pack(side="bottom", fill="x")

        # Pages, not one long sheet with a scrollbar. The first version scrolled a canvas that had
        # real widgets embedded in it, and on Windows that tears: the canvas has to move each child
        # window and repaint the exposed strip separately, so dragging the scrollbar smeared the
        # labels and entries vertically. No scrolling parameter fixes that, because the defect is
        # the embedded-window scrolling itself -- so the answer is to need no scrolling. Three short
        # pages, and the only part that could ever grow (the result) stays outside them.
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=10, pady=(8, 0))
        self.notebook = notebook
        self.pages: dict[str, ttk.Frame] = {}
        for key, name in TABS:
            page = ttk.Frame(notebook, padding=10)
            notebook.add(page, text=self.t(i18n_key=key))
            self.pages[name] = page

        outer = self.pages["artifacts"]
        self.content = outer

        # where the artifacts are
        source = ttk.LabelFrame(outer, text=self.t(i18n_key="group.artifacts"), padding=8)
        source.pack(fill="x")
        self.repo = tk.StringVar(value=self.settings.get("repo", os.getcwd()))
        self.artifacts = tk.StringVar(value=self.settings.get("artifacts"))
        scripted(source, self.t(i18n_key="field.project"), self.language).grid(
            row=0, column=0, sticky="w", **pad)
        ttk.Entry(source, textvariable=self.repo).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(source, text=self.t(i18n_key="button.browse"), command=self._browse_repo).grid(
            row=0, column=2, **pad)
        scripted(source, self.t(i18n_key="field.artifact_dir"), self.language).grid(
            row=1, column=0, sticky="w", **pad)
        ttk.Entry(source, textvariable=self.artifacts).grid(row=1, column=1, sticky="ew", **pad)
        ttk.Button(source, text=self.t(i18n_key="button.browse"),
                   command=self._browse_artifacts).grid(row=1, column=2, **pad)
        ttk.Button(source, text=self.t(i18n_key="button.scan"), command=self.on_scan).grid(
            row=1, column=3, **pad)
        source.columnconfigure(1, weight=1)

        # what was found
        found = ttk.LabelFrame(outer, text=self.t(i18n_key="group.proposed"), padding=8)
        found.pack(fill="both", expand=True)
        columns = (("take", "col.sign", 90), ("name", "col.file", 220), ("kind", "col.kind", 140),
                   ("size", "col.size", 110), ("signed", "col.state", 120), ("reason", "col.why", 400))
        self.tree = ttk.Treeview(found, columns=[name for name, _, _ in columns],
                                 show="headings", height=9, selectmode="none")
        for name, key, width in columns:
            self.tree.heading(name, text=self.t(i18n_key=key))
            self.tree.column(name, width=width, anchor="w", stretch=(name == "reason"))
        # Order matters, and getting it wrong is invisible until the words get longer: pack claims
        # space in the order it is called, so a bottom strip added after a widget that fills both
        # directions gets whatever is left, which is a sliver at the right. The strip goes first, the
        # scrollbar second, and the list takes what remains.
        selectors = ttk.Frame(found)
        selectors.pack(side="bottom", fill="x", pady=(6, 0))
        ttk.Button(selectors, text=self.t(i18n_key="button.select_all"),
                   command=lambda: self._select(True)).pack(side="left")
        ttk.Button(selectors, text=self.t(i18n_key="button.select_none"),
                   command=lambda: self._select(False)).pack(side="left", padx=6)
        tree_scroll = ttk.Scrollbar(found, orient="vertical", command=self.tree.yview)
        tree_scroll.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.bind("<Button-1>", self._toggle_row)
        self.tree.bind("<Double-1>", self._toggle_row)

        # who signs
        signing_page = self.pages["signing"]
        who = ttk.LabelFrame(signing_page, text=self.t(i18n_key="group.certificate"), padding=8)
        who.pack(fill="x")
        self.certificate = tk.StringVar()
        self.cert_box = ttk.Combobox(who, textvariable=self.certificate, state="readonly", width=90)
        self.cert_box.grid(row=0, column=0, columnspan=3, sticky="ew", **pad)
        ttk.Button(who, text=self.t(i18n_key="button.refresh"),
                   command=self.refresh_certificates).grid(row=0, column=3, **pad)
        ttk.Button(who, text=self.t(i18n_key="button.make_cert"),
                   command=self.on_create_certificate).grid(row=1, column=0, sticky="w", **pad)
        self.cert_note = ttk.Label(who, text="", foreground="#666")
        self.cert_note.grid(row=1, column=1, columnspan=3, sticky="w", **pad)
        who.columnconfigure(0, weight=1)

        # how it is signed
        options = ttk.LabelFrame(signing_page, text=self.t(i18n_key="group.signing"), padding=8)
        options.pack(fill="x", pady=(8, 0))
        self.note = tk.StringVar(value=self.settings.get("note"))
        self.output = tk.StringVar(value=self.settings.get("output"))
        self.ledger = tk.StringVar(value=self.settings.get(
            "ledger", os.path.join(os.getcwd(), ".onlysign", "signings.ndjson")))
        self.authorities = tk.StringVar(value=self.settings.get(
            "authorities", ", ".join(signer.DEFAULT_TIMESTAMP_AUTHORITIES)))
        self.allow_untimestamped = tk.BooleanVar(value=False)
        self.force = tk.BooleanVar(value=False)

        for row, (key, variable) in enumerate((("field.note", self.note),
                                               ("field.copy_to", self.output),
                                               ("field.record", self.ledger),
                                               ("field.authorities", self.authorities))):
            scripted(options, self.t(i18n_key=key), self.language).grid(
                row=row, column=0, sticky="w", **pad)
            span = 2 if key == "field.authorities" else 1
            ttk.Entry(options, textvariable=variable).grid(
                row=row, column=1, columnspan=span, sticky="ew", **pad)
            if span == 1:
                command = {"field.copy_to": self._browse_output,
                           "field.record": self._browse_ledger}.get(key)
                if command:
                    ttk.Button(options, text=self.t(i18n_key="button.browse"), command=command).grid(
                        row=row, column=2, **pad)
        ttk.Checkbutton(options, variable=self.allow_untimestamped,
                        text=self.t(i18n_key="check.untimestamped")).grid(
            row=4, column=0, columnspan=3, sticky="w", **pad)
        ttk.Checkbutton(options, variable=self.force,
                        text=self.t(i18n_key="check.force")).grid(
            row=5, column=0, columnspan=3, sticky="w", **pad)
        options.columnconfigure(1, weight=1)

        # what this machine will believe afterwards
        trust_page = self.pages["trust"]
        believing = ttk.LabelFrame(trust_page, text=self.t(i18n_key="group.trust"), padding=8)
        believing.pack(fill="x")
        self.trust_choice = tk.StringVar(value=workflow.TRUST_NONE)
        for index, choice in enumerate(workflow.TRUST_CHOICES):
            ttk.Radiobutton(believing, value=choice, variable=self.trust_choice,
                            text=self.t(i18n_key=TRUST_KEYS[choice]),
                            command=self._describe_trust).grid(row=0, column=index, sticky="w", **pad)
        note = ttk.Label(believing, text="", foreground="#666", wraplength=1000, justify="left")
        note.grid(row=1, column=0, columnspan=5, sticky="w", **pad)
        self.widgets["trust_note"] = note
        self._describe_trust()

        # where there is nowhere to sign
        self._build_mark_page(self.pages["mark"], pad)

        # the buttons, and what happened
        actions = ttk.Frame(bottom)
        actions.pack(fill="x", pady=(10, 0))
        self.dry_button = ttk.Button(actions, text=self.t(i18n_key="button.dry_run"),
                                     command=self.on_dry_run)
        self.dry_button.pack(side="left")
        self.sign_button = ttk.Button(actions, text=self.t(i18n_key="button.execute"),
                                      command=self.on_sign)
        self.sign_button.pack(side="left", padx=8)
        self.check_button = ttk.Button(actions, text=self.t(i18n_key="button.check"),
                                       command=self.on_check)
        self.check_button.pack(side="left")
        self.status = ttk.Label(actions, text=self.t(i18n_key="status.ready"))
        self.status.pack(side="right")

        report = ttk.LabelFrame(bottom, text=self.t(i18n_key="group.result"), padding=6)
        report.pack(fill="both", expand=True, pady=(8, 0))
        self.report = tk.Text(report, height=6, wrap="word", state="disabled",
                              font=font_of(self.language, "han"))
        self.report.pack(side="left", fill="both", expand=True)
        report_scroll = ttk.Scrollbar(report, orient="vertical", command=self.report.yview)
        report_scroll.pack(side="right", fill="y")
        self.report.configure(yscrollcommand=report_scroll.set)
        self.report.tag_configure("bad", foreground="#a00000")
        self.report.tag_configure("good", foreground="#006000")
        self.report.tag_configure("quiet", foreground="#666666")
        self.report.tag_configure("key", foreground="#000080")

    def _build_mark_page(self, page: ttk.Frame, pad: dict) -> None:
        """The fourth page: attribution on the formats that have no signature slot.

        This page decides nothing either. Which carrier applies to a file, whether the format is one
        that should be signed instead, and whether a mark's digest still describes the file are all
        asked of `mark` -- the same functions the `mark` verb calls. The one judgement the page makes
        is layout, and the one thing it insists on is the identity: a mark is a claim of ownership, so
        an empty one is refused here for the same reason the command line refuses it.
        """
        # what the page is for, said before anything can be pressed
        scripted(page, self.t(i18n_key="mark.what_it_is"), self.language, foreground="#666",
                 wraplength=980, justify="left").pack(fill="x")

        target = ttk.LabelFrame(page, text=self.t(i18n_key="group.mark_target"), padding=8)
        target.pack(fill="x", pady=(8, 0))
        self.mark_file = tk.StringVar(value=self.settings.get("mark_file"))
        self.mark_identity = tk.StringVar(
            value=self.settings.get("mark_identity",
                                    os.path.join(os.getcwd(), "IDENTITY.local.json")))
        self.mark_year = tk.StringVar(value=self.settings.get("mark_year",
                                                              str(datetime.date.today().year)))
        rows = (("field.mark_file", self.mark_file, self._browse_mark_file),
                ("field.mark_identity", self.mark_identity, self._browse_mark_identity))
        for index, (key, variable, command) in enumerate(rows):
            scripted(target, self.t(i18n_key=key), self.language).grid(
                row=index, column=0, sticky="w", **pad)
            ttk.Entry(target, textvariable=variable).grid(
                row=index, column=1, sticky="ew", **pad)
            ttk.Button(target, text=self.t(i18n_key="button.browse"), command=command).grid(
                row=index, column=2, **pad)
        scripted(target, self.t(i18n_key="field.mark_year"), self.language).grid(
            row=2, column=0, sticky="w", **pad)
        ttk.Entry(target, textvariable=self.mark_year, width=10).grid(
            row=2, column=1, sticky="w", **pad)
        target.columnconfigure(1, weight=1)

        actions = ttk.Frame(page)
        actions.pack(fill="x", pady=(8, 0))
        self.mark_preview_button = ttk.Button(actions, text=self.t(i18n_key="button.preview"),
                                              command=self.on_mark_preview)
        self.mark_preview_button.pack(side="left")
        self.mark_place_button = ttk.Button(actions, text=self.t(i18n_key="button.place"),
                                            command=self.on_mark)
        self.mark_place_button.pack(side="left", padx=8)
        self.mark_read_button = ttk.Button(actions, text=self.t(i18n_key="button.read_mark"),
                                           command=self.on_read_mark)
        self.mark_read_button.pack(side="left")

        # no file to mark, and the sector is the carrier itself
        sector = ttk.LabelFrame(page, text=self.t(i18n_key="group.boot"), padding=8)
        sector.pack(fill="x", pady=(8, 0))
        self.boot_out = tk.StringVar(value=self.settings.get("boot_out"))
        scripted(sector, self.t(i18n_key="field.boot_out"), self.language).grid(
            row=0, column=0, sticky="w", **pad)
        ttk.Entry(sector, textvariable=self.boot_out).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(sector, text=self.t(i18n_key="button.browse"),
                   command=self._browse_boot_out).grid(row=0, column=2, **pad)
        self.build_sector_button = ttk.Button(sector, text=self.t(i18n_key="button.build_sector"),
                                              command=lambda: self.on_build_sector(False))
        self.build_sector_button.grid(row=1, column=0, columnspan=2, sticky="w", **pad)
        self.build_floppy_button = ttk.Button(sector, text=self.t(i18n_key="button.build_floppy"),
                                              command=lambda: self.on_build_sector(True))
        self.build_floppy_button.grid(row=2, column=0, columnspan=2, sticky="w", **pad)
        scripted(sector, self.t(i18n_key="boot.why"), self.language, foreground="#666",
                 wraplength=980, justify="left").grid(row=3, column=0, columnspan=3, sticky="w", **pad)
        sector.columnconfigure(1, weight=1)

        # The signing buttons belong to the signing page, and leaving them live on this one would
        # offer an action that has nothing to do with what is on screen. They are switched off when
        # this page is the one showing, and back on when it is not -- see `_on_tab_changed`.
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

    def _on_tab_changed(self, _event=None) -> None:
        """Keep the signing buttons to their own page, and the marking buttons to theirs.

        Guarded, because Tk can deliver this while the pages are still being built: `_apply_language`
        selects a page and the event arrives before every page exists, and a handler that assumed a
        finished window would take the whole window down on a language switch.
        """
        if not hasattr(self, "notebook") or "mark" not in getattr(self, "pages", {}):
            return
        if not hasattr(self, "mark_place_button"):
            return
        if not self.busy:
            self._set_buttons("normal")

    def _set_buttons(self, state: str) -> None:
        """Every action button, and which page it belongs to.

        One place, because the alternative is the state of a button depending on which of two
        functions last touched it -- and the sibling verb is the one that gets forgotten when a new
        button is added.
        """
        on_mark = self.notebook.index("current") == self.notebook.index(self.pages["mark"])
        for button in (self.dry_button, self.sign_button, self.check_button):
            button.configure(state="disabled" if (state == "disabled" or on_mark) else "normal")
        for button in (self.mark_preview_button, self.mark_place_button, self.mark_read_button,
                       self.build_sector_button, self.build_floppy_button):
            button.configure(state="disabled" if (state == "disabled" or not on_mark) else "normal")

    # --- marking -------------------------------------------------------------- #

    def _browse_mark_file(self) -> None:
        chosen = filedialog.askopenfilename(title=self.t(i18n_key="pick.mark_file"))
        if chosen:
            self.mark_file.set(chosen)

    def _browse_mark_identity(self) -> None:
        chosen = filedialog.askopenfilename(title=self.t(i18n_key="pick.mark_identity"),
                                            filetypes=[("JSON", "*.json"), ("all files", "*.*")])
        if chosen:
            self.mark_identity.set(chosen)

    def _browse_boot_out(self) -> None:
        chosen = filedialog.asksaveasfilename(title=self.t(i18n_key="pick.mark_out"))
        if chosen:
            self.boot_out.set(chosen)

    def _mark_names(self) -> tuple[str, list[str]]:
        """Who the mark belongs to, read from a file -- and nothing invented when it is absent.

        A mark that fills in a name it was not given is not a mark, so this refuses rather than
        falling back to anything, which is what the command line does with the same function.
        """
        where = self.mark_identity.get().strip()
        if not where:
            self.say(self.t(i18n_key="say.mark_no_identity"), "bad")
            return "", []
        try:
            primary, secondary = mark.names_from(where)
        except ValueError as exc:
            self.say(self.t(i18n_key="say.mark_failed", error=exc), "bad")
            return "", []
        if not primary:
            self.say(self.t(i18n_key="say.mark_failed", error=where), "bad")
        return primary, secondary

    def _say_the_verdict(self, path: str) -> tuple[str, object | None]:
        """What this file is, which carrier it takes, and the writer -- all from `mark`."""
        if not os.path.isfile(path):
            self.say(self.t(i18n_key="say.mark_failed", error=path), "bad")
            return "", None
        kind = pe.identify(path)
        carrier, word, work = mark.carrier_for(path, signable=pe.signable(kind))
        if carrier == mark.KIND_SIGNED:
            self.say(self.t(i18n_key="say.mark_carrier",
                            carrier=self.t(i18n_key="carrier.signed")), "bad")
            self.say("     " + pe.describe(kind))
            return carrier, None
        if work is None:
            self.say(self.t(i18n_key="say.mark_carrier",
                            carrier=self.t(i18n_key="carrier.no-carrier")), "bad")
            return carrier, None
        self.say(self.t(i18n_key="say.mark_carrier",
                        carrier=self.t(i18n_key="carrier." + word)), "key")
        return carrier, work

    def on_mark_preview(self) -> None:
        """What would be written, and where -- with nothing written."""
        path = self.mark_file.get().strip()
        primary, secondary = self._mark_names()
        if not primary:
            return
        self.clear_report()
        self.say(self.t(i18n_key="say.mark_preview"), "quiet")
        carrier, work = self._say_the_verdict(path)
        if work is None:
            return
        body = mark.mark_line(primary=primary, secondary=secondary, year=self.mark_year.get().strip(),
                              kind="placeholder")
        self.say("     " + body, "quiet")
        self.say(self.t(i18n_key="say.mark_digest", digest=self.t(i18n_key="say.mark_no_digest")),
                 "quiet")

    def on_mark(self) -> None:
        path = self.mark_file.get().strip()
        primary, secondary = self._mark_names()
        if not primary:
            return
        self.clear_report()
        carrier, work = self._say_the_verdict(path)
        if work is None:
            return
        year = self.mark_year.get().strip()

        def placing():
            return work(path, primary=primary, secondary=secondary, year=year, digest=True)

        def done(payload):
            self._finish(payload)
            kind, value = payload
            if kind == "failed":
                self.say(self.t(i18n_key="say.mark_failed", error=value), "bad")
                return
            self._say_a_mark(value)

        self._run(placing, done)

    def _say_a_mark(self, written: dict) -> None:
        """One mark, as it was written, plus what reading it back says about the file."""
        self.mark_file.set(written.get("path", self.mark_file.get()))
        self.say(self.t(i18n_key="say.mark_placed"), "good")
        self.say("     " + written.get("line", ""))
        if written.get("digest"):
            self.say(self.t(i18n_key="say.mark_digest", digest=written["digest"]), "quiet")
        else:
            self.say(self.t(i18n_key="say.mark_no_digest"), "quiet")
        self.say(self.t(i18n_key="say.mark_strength",
                        strength=self.t(i18n_key="mark.strength." + written.get("kind", ""))), "quiet")
        # Reading it back is not ceremony: the carrier wrote it, and whether the same bytes come out
        # again is the only thing that says the write landed where a reader will look.
        read = self._read_mark(written.get("path", ""))
        if read:
            self._say_what_came_back(read)

    def _read_mark(self, path: str) -> dict | None:
        if not path or not os.path.isfile(path):
            return None
        if mark.zip_eocd_at(path) is not None:
            return mark.read_zip_mark(path)
        if mark.tar_mark_offset(path) is not None or mark.looks_like_tar(path):
            return mark.read_tar_mark(path)
        if mark.iso_app_use_offset(path) is not None:
            return mark.read_iso_mark(path)
        return None

    def _say_what_came_back(self, found: dict) -> None:
        if not found.get("marked"):
            self.say(self.t(i18n_key="say.mark_none"), "bad")
            return
        self.say(self.t(i18n_key="say.mark_read"), "key")
        self.say("     " + found.get("raw", ""))
        if found.get("sha256"):
            agrees = bool(found.get("digest_matches"))
            self.say(self.t(i18n_key="say.mark_agrees" if agrees else "say.mark_disagrees"),
                     "good" if agrees else "bad")

    def on_read_mark(self) -> None:
        path = self.mark_file.get().strip()
        self.clear_report()
        found = self._read_mark(path)
        if found is None:
            self.say(self.t(i18n_key="say.mark_unreadable"), "bad")
            return
        self._say_what_came_back(found)

    def on_build_sector(self, floppy: bool) -> None:
        """The mark itself, in 512 bytes, for when there is no file to carry it."""
        out = self.boot_out.get().strip()
        primary, secondary = self._mark_names()
        if not primary:
            return
        if not out:
            self.say(self.t(i18n_key="say.mark_failed", error=self.t(i18n_key="field.boot_out")), "bad")
            return
        self.clear_report()
        body = mark.mark_line(primary=primary, secondary=secondary, year=self.mark_year.get().strip(),
                              kind="boot-sector")

        def building():
            size = (bootmark.write_image(out, body) if floppy else bootmark.write(out, body))
            return {"path": out, "size": size, "line": body, "floppy": floppy}

        def done(payload):
            self._finish(payload)
            kind, value = payload
            if kind == "failed":
                self.say(self.t(i18n_key="say.mark_failed", error=value), "bad")
                return
            what = self.t(i18n_key="carrier.boot sector in a 1.44 MB image" if value["floppy"]
                          else "carrier.boot sector")
            self.say(self.t(i18n_key="say.mark_boot", path=value["path"], size=value["size"],
                            what=what), "good")
            self.say("     " + value["line"])
            self.say(self.t(i18n_key="say.mark_strength",
                            strength=self.t(i18n_key="mark.strength.boot-sector")), "quiet")

        self._run(building, done)

    # --- small helpers -------------------------------------------------------- #

    def _browse_repo(self) -> None:
        chosen = filedialog.askdirectory(title=self.t(i18n_key="pick.project"))
        if chosen:
            self.repo.set(chosen)

    def _browse_artifacts(self) -> None:
        chosen = filedialog.askdirectory(title=self.t(i18n_key="pick.artifacts"))
        if chosen:
            self.artifacts.set(chosen)

    def _browse_output(self) -> None:
        chosen = filedialog.askdirectory(title=self.t(i18n_key="pick.output"))
        if chosen:
            self.output.set(chosen)

    def _browse_ledger(self) -> None:
        chosen = filedialog.asksaveasfilename(title=self.t(i18n_key="pick.ledger"),
                                              defaultextension=".ndjson")
        if chosen:
            self.ledger.set(chosen)

    def say(self, message: str, tag: str = "") -> None:
        self.report.configure(state="normal")
        self.report.insert("end", message + "\n", tag)
        self.report.see("end")
        self.report.configure(state="disabled")

    def clear_report(self) -> None:
        self.report.configure(state="normal")
        self.report.delete("1.0", "end")
        self.report.configure(state="disabled")

    def _drain(self) -> None:
        """Collect anything a worker finished, then look again shortly."""
        try:
            while True:
                action, payload = self.results.get_nowait()
                action(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def _run(self, work, done) -> None:
        """Run something slow without freezing the window."""
        if self.busy:
            return
        self.busy = True
        self._set_buttons("disabled")
        self.status.configure(text=self.t(i18n_key="status.working"))

        def runner():
            try:
                self.results.put((done, ("ok", work())))
            except Exception as exc:                     # noqa: BLE001 - reported in the window
                self.results.put((done, ("failed", exc)))

        threading.Thread(target=runner, daemon=True).start()

    def _finish(self, payload) -> None:
        self.busy = False
        self._set_buttons("normal")
        self.status.configure(text=self.t(i18n_key="status.ready"))

    # --- the certificate ------------------------------------------------------ #

    def refresh_certificates(self) -> None:
        def done(payload):
            self._finish(payload)
            kind, value = payload
            if kind == "failed":
                self.say(self.t(i18n_key="say.cert_failed", error=value), "bad")
                return
            self.certificates = [c for c in value if c.permits_code_signing and not c.expired]
            usable = [c.short() for c in self.certificates]
            self.cert_box.configure(values=usable)
            if usable and self.certificate.get() not in usable:
                self.certificate.set(usable[0])
            if not usable:
                self.cert_note.configure(text=self.t(i18n_key="cert.none"))
            else:
                chosen = self._chosen_certificate()
                if chosen is None:
                    self.cert_note.configure(text="")
                    return
                issued = (self.t(i18n_key="cert.self_signed") if chosen.self_signed
                          else self.t(i18n_key="cert.issued_by", issuer=chosen.issuer))
                self.cert_note.configure(
                    text=self.t(i18n_key="cert.expires", days=chosen.days_left()) + "; " + issued)

        self._run(certs.list_certificates, done)

    def _chosen_certificate(self) -> certs.Certificate | None:
        wanted = self.certificate.get()
        for candidate in self.certificates:
            if candidate.short() == wanted:
                return candidate
        return None

    def on_create_certificate(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title(self.t(i18n_key="dialog.make_cert.title"))
        dialog.transient(self.root)
        scripted(dialog, self.t(i18n_key="dialog.make_cert.question"), self.language,
                 wraplength=520, justify="left").grid(row=0, column=0, padx=8, pady=(8, 4), sticky="w")
        subject = tk.StringVar(value="CN=My Code Signing")
        ttk.Entry(dialog, textvariable=subject, width=46).grid(row=1, column=0, padx=8, sticky="ew")
        scripted(dialog, self.t(i18n_key="dialog.make_cert.explain"), self.language,
                 foreground="#666", wraplength=520, justify="left").grid(
            row=2, column=0, padx=8, sticky="w")
        years = tk.IntVar(value=5)
        scripted(dialog, self.t(i18n_key="dialog.make_cert.years"), self.language).grid(
            row=3, column=0, padx=8, pady=(8, 0), sticky="w")
        ttk.Spinbox(dialog, from_=1, to=20, textvariable=years, width=6).grid(
            row=4, column=0, padx=8, sticky="w")

        def create():
            where = filedialog.askdirectory(title=self.t(i18n_key="dialog.make_cert.where"))
            if not where:
                return
            dialog.destroy()
            import base64
            import secrets
            password = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
            stem = "".join(ch if ch.isalnum() else "-"
                           for ch in subject.get().split("CN=")[-1]) or "certificate"

            def done(payload):
                self._finish(payload)
                kind, value = payload
                if kind == "failed":
                    self.say(self.t(i18n_key="say.make_failed", error=value), "bad")
                    return
                self.say(self.t(i18n_key="say.made", subject=value.subject), "good")
                self.say(self.t(i18n_key="say.public_half",
                                path=os.path.join(where, stem + ".cer")))
                self.say(self.t(i18n_key="say.private_half",
                                path=os.path.join(where, stem + ".pfx")), "bad")
                self.say(self.t(i18n_key="say.password", password=password), "bad")
                self.say(self.t(i18n_key="say.password_once"), "quiet")
                self.refresh_certificates()

            self._run(lambda: certs.create_self_signed(
                subject.get(), years=years.get(), password=password,
                pfx_path=os.path.join(where, stem + ".pfx"),
                cer_path=os.path.join(where, stem + ".cer")), done)

        ttk.Button(dialog, text=self.t(i18n_key="dialog.make_cert.create"),
                   command=create).grid(row=5, column=0, padx=8, pady=10, sticky="w")

    # --- about ---------------------------------------------------------------- #

    def _about_mark(self, parent):
        """The application's own mark, in colour.

        A console cannot show this -- the notice's drawing is characters, one colour, because that is
        what a console has -- but a window can, so the one place the real image appears is here. If
        the file is not beside the build the heading simply has no picture; a missing decoration is
        not a reason for the window to fail.
        """
        roots = [os.path.dirname(os.path.dirname(os.path.abspath(__file__)))]
        bundled = getattr(sys, "_MEIPASS", "")
        if bundled:
            roots.append(bundled)
        if getattr(sys, "frozen", False):
            roots.append(os.path.dirname(sys.executable))
        for root in roots:
            for name in ("onlysign-256.png", "onlysign.png"):
                path = os.path.join(root, "mark", name)
                if not os.path.isfile(path):
                    continue
                try:
                    # Tk 8.6 and later read PNG directly, so no imaging library is needed for this.
                    image = tk.PhotoImage(file=path)
                except tk.TclError:
                    continue
                label = ttk.Label(parent, image=image)
                label.image = image          # Tk holds only a weak reference; keep one here
                return label
        return None

    def on_about(self) -> None:
        from . import notice
        dialog = tk.Toplevel(self.root)
        dialog.title(self.t(i18n_key="about.title"))
        dialog.transient(self.root)
        body = ttk.Frame(dialog, padding=12)
        body.pack(fill="both", expand=True)
        mark = self._about_mark(body)
        if mark is not None:
            mark.pack(pady=(0, 8))
        ttk.Label(body, text=self.t(i18n_key="app.name"),
                  font=wordmark_font(i18n.FONT_SIZE + 8)).pack(anchor="w")
        banner = ttk.Label(body, text=ascii_banner(), font=wordmark_font(i18n.FONT_SIZE + 2))
        banner.pack(anchor="w", pady=(6, 10))
        scripted(body, self.t(i18n_key="about.purpose"), self.language,
                 justify="left").pack(anchor="w", pady=(0, 8))
        # The notice is a drawing made of characters, so it needs a fixed pitch to keep its shape --
        # the one place in this window where the font is chosen for geometry rather than for script.
        text = tk.Text(body, height=22, width=64, wrap="none", state="normal",
                       font=(i18n.ART_FONT.get(self.language, "SimSun"), i18n.FONT_SIZE - 1),
                       background="#101014", foreground="#e8e8f0", relief="flat")
        text.insert("1.0", notice.text(self.language).rstrip())
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)
        ttk.Button(body, text=self.t(i18n_key="about.close"), command=dialog.destroy).pack(
            anchor="e", pady=(10, 0))

    # --- saying what the engine did, in this window's language ----------------- #
    #
    # The engine reports structures and also prints English prose for the command line. The window
    # uses the structures and writes its own sentences, because a window that pasted the engine's
    # words would be an English window wearing a translation. A raw error message is the exception:
    # it is shown as the engine wrote it, since a diagnostic is something to match against a log.

    def kind_name(self, kind: str) -> str:
        return self.t(i18n_key="kind." + (kind or "unknown"))

    def state_name(self, signed: bool) -> str:
        return self.t(i18n_key="state.signed" if signed else "state.unsigned")

    def why_text(self, candidate) -> str:
        parts = [self.t(i18n_key=code, **fields) for code, fields in (candidate.why or [])]
        return " | ".join(parts) if parts else candidate.reason

    def _preview_lines(self, plan) -> list[str]:
        lines = [self.t(i18n_key="preview.heading"),
                 self.t(i18n_key="preview.certificate", subject=plan.certificate().subject),
                 self.t(i18n_key="preview.ledger", path=plan.ledger_at())]
        if plan.allow_untimestamped:
            lines.append(self.t(i18n_key="preview.no_timestamps"))
        else:
            lines.append(self.t(i18n_key="preview.timestamps",
                                authorities=", ".join(plan.timestamp_authorities)))
        if plan.output_dir:
            lines.append(self.t(i18n_key="preview.copy", path=plan.output_dir))
        lines.append(self.t(i18n_key="preview.trust",
                            what=self.t(i18n_key=TRUST_KEYS.get(plan.trust, "trust.none"))))
        lines.append(self.t(i18n_key="preview.files"))
        for path in plan.paths:
            if not os.path.isfile(path):
                lines.append(self.t(i18n_key="preview.missing", path=path))
                continue
            lines.append(self.t(i18n_key="preview.file",
                                name=os.path.basename(path), size=os.path.getsize(path),
                                state=self.state_name(signer.own_signature(path).present)))
        return lines

    def _outcome_lines(self, outcome) -> list[str]:
        lines = [self.t(i18n_key="outcome.summary",
                        signed=len(outcome.signed), skipped=len(outcome.skipped),
                        failed=len(outcome.failed), copied=len(outcome.copies))]
        for result in outcome.results:
            name = os.path.basename(result.path)
            if result.ok:
                lines.append(self.t(i18n_key="outcome.signed", name=name))
            elif result.skipped:
                lines.append(self.t(i18n_key="outcome.skipped", name=name,
                                    why=self.t(i18n_key="outcome.not_an_artifact",
                                               kind=self.kind_name(result.kind))))
            else:
                lines.append(self.t(i18n_key="outcome.failed", name=name, why=result.error))
        for _source, target in outcome.copies:
            lines.append(self.t(i18n_key="outcome.copied",
                                source=os.path.basename(_source), target=target))
        for store in outcome.trust_written:
            lines.append(self.t(i18n_key="outcome.trusted", store=store))
        return lines

    def _audit_summary(self, report) -> str:
        counts = report.counts()
        return self.t(i18n_key="audit.summary", records=len(report.findings),
                      unchanged=counts.get(audit.UNCHANGED, 0),
                      changed=counts.get(audit.CHANGED, 0),
                      signer=counts.get(audit.SIGNER_DIFFERS, 0),
                      unsigned=counts.get(audit.NOW_UNSIGNED, 0),
                      gone=counts.get(audit.GONE, 0))

    # --- the list of artifacts ------------------------------------------------ #

    def _toggle_row(self, event) -> None:
        row = self.tree.identify_row(event.y)
        if not row or self.tree.identify_column(event.x) != "#1":
            return
        index = self.tree.index(row)
        self.candidates[index].selected = not self.candidates[index].selected
        self.tree.set(row, "take", "yes" if self.candidates[index].selected else "no")

    def _select(self, value: bool) -> None:
        for index, candidate in enumerate(self.candidates):
            candidate.selected = value
            self.tree.set(self.tree.get_children()[index], "take", "yes" if value else "no")

    def on_scan(self) -> None:
        repo, artifacts = self.repo.get().strip(), self.artifacts.get().strip()
        self.settings.put("repo", repo)
        self.settings.put("artifacts", artifacts)
        self.settings.save()
        self.say(self.t(i18n_key="say.scanning", where=artifacts or repo), "quiet")

        def done(payload):
            self._finish(payload)
            kind, value = payload
            if kind == "failed":
                self.say(self.t(i18n_key="say.scan_failed", error=value), "bad")
                return
            self.candidates = value.candidates
            self.tree.delete(*self.tree.get_children())
            for candidate in self.candidates:
                self.tree.insert("", "end", values=(
                    "yes" if candidate.selected else "no",
                    os.path.basename(candidate.path),
                    self.kind_name(candidate.kind),
                    candidate.size,
                    self.state_name(candidate.signed),
                    self.why_text(candidate),
                ))
            self.say(self.t(i18n_key="say.found", count=len(self.candidates), examined=value.examined),
                     "good" if self.candidates else "")
            for code, fields in (value.note_codes or []):
                self.say(self.t(i18n_key="say.note", text=self.t(i18n_key=code, **fields)), "quiet")
            if not value.note_codes:
                for note in value.notes:
                    self.say(self.t(i18n_key="say.note", text=note), "quiet")

        self._run(lambda: discover.scan(repo, artifacts), done)

    # --- signing -------------------------------------------------------------- #

    def _plan(self) -> workflow.Plan:
        certificate = self._chosen_certificate()
        if certificate is None:
            raise ValueError(self.t(i18n_key="cert.choose"))
        chosen = [c.path for c in self.candidates if c.selected]
        if not chosen:
            raise ValueError(self.t(i18n_key="cert.choose_files"))
        authorities = tuple(a.strip() for a in self.authorities.get().split(",") if a.strip())
        return workflow.Plan(
            paths=chosen, thumbprint=certificate.thumbprint, note=self.note.get(),
            ledger_path=self.ledger.get(), timestamp_authorities=authorities,
            allow_untimestamped=self.allow_untimestamped.get(), force=self.force.get(),
            output_dir=self.output.get(), trust=self.trust_choice.get())

    def _remember(self) -> None:
        for key, variable in (("note", getattr(self, "note", None)),
                              ("output", getattr(self, "output", None)),
                              ("ledger", getattr(self, "ledger", None)),
                              ("authorities", getattr(self, "authorities", None)),
                              ("repo", getattr(self, "repo", None)),
                              ("artifacts", getattr(self, "artifacts", None)),
                              ("mark_file", getattr(self, "mark_file", None)),
                              ("mark_identity", getattr(self, "mark_identity", None)),
                              ("mark_year", getattr(self, "mark_year", None)),
                              ("boot_out", getattr(self, "boot_out", None))):
            if variable is not None:
                self.settings.put(key, variable.get())
        self.settings.save()

    def on_dry_run(self) -> None:
        try:
            plan = self._plan()
        except ValueError as exc:
            self.say(str(exc), "bad")
            return
        self._remember()
        self.say("")
        self.say(self.t(i18n_key="say.dry_run_heading"), "quiet")
        try:
            for line in self._preview_lines(plan):
                self.say(line)
        except Exception as exc:                          # noqa: BLE001
            self.say(self.t(i18n_key="say.preview_failed", error=exc), "bad")

    def on_sign(self) -> None:
        try:
            plan = self._plan()
        except ValueError as exc:
            self.say(str(exc), "bad")
            return
        self._remember()
        if not messagebox.askyesno(
                self.t(i18n_key="dialog.confirm.title"),
                self.t(i18n_key="dialog.confirm.body", count=len(plan.paths),
                       subject=plan.certificate().subject, ledger=plan.ledger_at())):
            return
        self.say("")
        self.say(self.t(i18n_key="say.signing_heading"), "quiet")

        def done(payload):
            self._finish(payload)
            kind, value = payload
            if kind == "failed":
                self.say(self.t(i18n_key="say.sign_failed", error=value), "bad")
                return
            self.say(self.t(i18n_key="say.ledger", path=plan.ledger_at()), "quiet")
            for line in self._outcome_lines(value):
                self.say(line, "bad" if value.failed else "")
            self.say("")
            if value.failed:
                self.say(self.t(i18n_key="signing_failed"), "bad")
            else:
                self.say(ascii_banner(), "good")

        self._run(lambda: workflow.execute(plan, dry_run=False), done)

    def on_check(self) -> None:
        path = self.ledger.get().strip()
        self.say("")
        self.say(self.t(i18n_key="say.checking", path=path), "quiet")

        def done(payload):
            self._finish(payload)
            kind, value = payload
            if kind == "failed":
                self.say(self.t(i18n_key="say.check_failed", error=value), "bad")
                return
            for finding in value.findings:
                tag = "bad" if finding.verdict in audit.ALARMING else ""
                self.say(f"[{finding.when}] {finding.name}  "
                         f"{self.t(i18n_key='verdict.' + finding.verdict)}", tag)
                if finding.replaced_by:
                    self.say(self.t(i18n_key="audit.replaced_by",
                                    when=str(finding.replaced_by.get("t"))[:19]), "quiet")
            self.say(self._audit_summary(value),
                     "bad" if value.needing_attention() else "good")

        self._run(lambda: audit.audit(path), done)


# Which string names each trust store choice. Kept beside the window rather than in the engine,
# because it is a choice of words and the engine's words are the ones a script reads.
TRUST_KEYS = {
    workflow.TRUST_NONE: "trust.none",
    workflow.TRUST_USER_PUBLISHERS: "trust.user_publishers",
    workflow.TRUST_USER_ROOT: "trust.user_root",
    workflow.TRUST_USER_BOTH: "trust.user_both",
    workflow.TRUST_MACHINE_BOTH: "trust.machine_both",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="onlysign-gui", description="The OnlySign window.")
    parser.add_argument("--check", action="store_true",
                        help="build the window and close it again, to prove it can be built")
    parser.add_argument("--tabs", action="store_true",
                        help="print the pages the window offers, so a built executable can be "
                             "asked what is inside it rather than assumed to carry it")
    parser.add_argument("--settings", default="", help="where the window remembers things")
    parser.add_argument("--lang", default="", help="zh, en or ja")
    args = parser.parse_args(argv)

    settings_path = args.settings or os.path.join(os.getcwd(), ".onlysign", SETTINGS_NAME)
    settings = Settings(settings_path)
    if args.lang:
        settings.put("language", i18n.normalise(args.lang) or args.lang)

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"no display is available, so the window cannot open: {exc}")
        return 1
    window = Window(root, settings)
    if args.tabs:
        # Asked of the window, not read off this file: a page that was written and never added to
        # the notebook is a page nobody can reach, and that is exactly what a build log cannot see.
        # The wording of the names is the window's language, so what is compared is the count and
        # which page sits where -- the keys, not the words.
        root.update_idletasks()
        found = [window.notebook.tab(index, "text")
                 for index in range(window.notebook.index("end"))]
        expected = [window.t(i18n_key=key) for key in TAB_KEYS]
        root.destroy()
        print(f"the window offers {len(found)} page(s): " + ", ".join(found))
        print("expected, in this language: " + ", ".join(expected))
        if len(found) != len(expected):
            print(f"missing: expected {len(expected)} page(s), found {len(found)}")
            return 1
        return 0
    if args.check:
        # Prove the window in every language it claims to speak, not just the one it opens in, and
        # prove the About window can find its mark -- a picture that silently goes missing in a
        # packaged build is not something a build log ever mentions.
        for code in i18n.LANGUAGES:
            window._apply_language(code)
            root.update_idletasks()
        root.update_idletasks()
        art = window._about_mark(root)
        picture = (f"{art.image.width()}x{art.image.height()}" if art is not None
                   else "absent, and the About window goes without it")
        pages = [window.notebook.tab(index, "text") for index in range(window.notebook.index("end"))]
        root.destroy()
        print(f"the window was built, switched language twice, and closed; mark {picture}")
        print("pages: " + ", ".join(pages))
        return 0
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
