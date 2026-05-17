"""
dayzdriv GUI — tkinter launcher for the dayzdriv hypervisor driver project.
Dependencies: pystray, pillow  (python -m pip install pystray pillow)
"""

import ctypes
import json
import re
import shutil
import subprocess
import sys
import threading
import time
import queue
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import ttk, scrolledtext, messagebox

import pystray
from PIL import Image, ImageDraw

# ── paths ─────────────────────────────────────────────────────────────────────
ROOT        = Path(r"F:\vsprojs\dayzdriv")
BIN         = ROOT / "bin" / "dayzdriv.sys"
PDB         = ROOT / "bin" / "dayzdriv.pdb"
SRC_DIR     = ROOT / "src"
DRVLOG      = ROOT / "logs" / "dayzdriv.log"
DUMPS_DIR   = ROOT / "dumps"
WIN_DUMPS   = Path(r"C:\Windows\Minidump")
KDMAPPER    = Path(r"J:\Downloads\kdmapper-master\kdmapper-master\x64\Release\kdmapper_Release.exe")
CDB         = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe")
DBH         = Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbh.exe")
VSCODE      = Path(r"G:\Microsoft VS Code\bin\code.cmd")
SYMPATH     = rf"srv*C:\Symbols*https://msdl.microsoft.com/download/symbols;{ROOT / 'bin'}"
REBUILD_BAT = ROOT / "scripts" / "rebuild.bat"
CRASH_LOG   = ROOT / "logs" / "crash_history.json"
SESSION_LOG = ROOT / "logs" / "session.log"
FIXES_MD    = ROOT / "FIXES.md"

BUILD_STEPS = 7

# ── colours ───────────────────────────────────────────────────────────────────
BG      = "#1a1a1a"
BG2     = "#242424"
BG3     = "#2e2e2e"
FG      = "#e0e0e0"
FG_DIM  = "#888888"
GREEN   = "#4caf50"
RED     = "#f44336"
YELLOW  = "#ffc107"
BLUE    = "#2196f3"
ORANGE  = "#ff7043"
PURPLE  = "#7b1fa2"
CYAN    = "#00bcd4"
ACCENT  = "#37474f"

MONO  = ("Consolas", 9)
LABEL = ("Segoe UI", 9)
BOLD  = ("Segoe UI", 9, "bold")
SMALL = ("Segoe UI", 8)

# ── driver log tag map: [TAG] → colour ────────────────────────────────────────
LOG_TAG_COLORS = {
    "ENTRY":  "#ce93d8",  # purple-ish
    "INFO":   CYAN,
    "EPT":    "#80cbc4",  # teal
    "IPC":    "#ffcc02",  # gold
    "CALIB":  "#a5d6a7",  # light green
    "MBEC":   "#80deea",
    "MSR":    "#b0bec5",
    "VMCS":   "#ff8a65",  # orange
    "ERROR":  RED,
    "FAIL":   RED,
    "BSOD":   RED,
    "CRASH":  RED,
    "WARN":   YELLOW,
}

BUGCHECK_DESCRIPTIONS = {
    "0x1":  "APC_INDEX_MISMATCH",
    "0x3b": "SYSTEM_SERVICE_EXCEPTION",
    "0x50": "PAGE_FAULT_IN_NONPAGED_AREA",
    "0x7e": "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED",
    "0x7f": "UNEXPECTED_KERNEL_MODE_TRAP",
    "0x9f": "DRIVER_POWER_STATE_FAILURE",
    "0xa":  "IRQL_NOT_LESS_OR_EQUAL",
    "0xc2": "BAD_POOL_CALLER",
    "0xc4": "DRIVER_VERIFIER_DETECTED_VIOLATION",
    "0xc5": "DRIVER_CORRUPTED_EXPOOL",
    "0xd1": "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    "0xe":  "NO_USER_MODE_CONTEXT",
    "0x1e": "KMODE_EXCEPTION_NOT_HANDLED",
    "0x44": "MULTIPLE_IRP_COMPLETE_REQUESTS",
    "0x101": "CLOCK_WATCHDOG_TIMEOUT",
    "0x109": "CRITICAL_STRUCTURE_CORRUPTION",
    "0x133": "DPC_WATCHDOG_VIOLATION",
    "0x139": "KERNEL_SECURITY_CHECK_FAILURE",
    "0x13a": "KERNEL_MODE_HEAP_CORRUPTION",
    "0x154": "UNEXPECTED_STORE_EXCEPTION",
    "0x1a": "MEMORY_MANAGEMENT",
}


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _si() -> subprocess.STARTUPINFO:
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return si


def _run_hidden(args, **kw):
    return subprocess.run(args, startupinfo=_si(),
                          creationflags=subprocess.CREATE_NO_WINDOW, **kw)


# ── tray icon ─────────────────────────────────────────────────────────────────

def _make_tray_icon(color: str) -> Image.Image:
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    r, g, b = int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)
    d.ellipse([4, 4, 60, 60], fill=(r, g, b, 255))
    return img


# ── crash history ─────────────────────────────────────────────────────────────

def _load_crash_history() -> list:
    try:
        if CRASH_LOG.exists():
            return json.loads(CRASH_LOG.read_text())
    except Exception:
        pass
    return []


def _save_crash_entry(entry: dict):
    history = _load_crash_history()
    history.append(entry)
    CRASH_LOG.parent.mkdir(exist_ok=True)
    CRASH_LOG.write_text(json.dumps(history, indent=2))


def _update_crash_entry_note(dump_name: str, note: str):
    history = _load_crash_history()
    for entry in history:
        if entry.get("dump") == dump_name:
            entry["note"] = note
            break
    CRASH_LOG.write_text(json.dumps(history, indent=2))


def _extract_crash_fields(cdb_output: str) -> dict:
    fields = {}
    patterns = {
        "bugcheck": r"BUGCHECK_CODE:\s+(\S+)",
        "symbol":   r"SYMBOL_NAME:\s+(\S+)",
        "image":    r"IMAGE_NAME:\s+(\S+)",
        "bucket":   r"FAILURE_BUCKET_ID:\s+(.+)",
        "faulting": r"FAULTING_IP:\s+(.+)",
        "offset":   r"(?:dayzdriv|DayZHV)\+0x([0-9a-fA-F]+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, cdb_output, re.IGNORECASE)
        if m:
            fields[key] = m.group(1).strip()
    return fields


# ── session log ───────────────────────────────────────────────────────────────

def _session_log(msg: str):
    SESSION_LOG.parent.mkdir(exist_ok=True)
    with open(SESSION_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}\n")


# ── PDB source resolution ─────────────────────────────────────────────────────

def _resolve_offset_to_source(offset_hex: str) -> str | None:
    if not DBH.exists() or not PDB.exists():
        return None
    try:
        addr = int(offset_hex, 16)
        result = _run_hidden([str(DBH), str(PDB), "addr", hex(addr)],
                             capture_output=True, text=True, timeout=10)
        for line in result.stdout.splitlines():
            m = re.search(r'([A-Za-z]:\\[^\s:]+\.[ch])\s*[:(]\s*(\d+)', line)
            if m:
                return f"{m.group(1)}:{m.group(2)}"
            m2 = re.search(r'(\w+\.[ch])\s*[:(]\s*(\d+)', line)
            if m2:
                return f"{SRC_DIR / m2.group(1)}:{m2.group(2)}"
    except Exception:
        pass
    return None


# ── FIXES.md ──────────────────────────────────────────────────────────────────

def _append_fixes_entry(fields: dict, source_loc: str | None):
    entry = (
        f"\n## BSOD — {datetime.now().strftime('%Y-%m-%d')}\n"
        f"- **Bugcheck**: `{fields.get('bugcheck','?')}`\n"
        f"- **Symbol**: `{fields.get('symbol','?')}`\n"
        f"- **Image**: `{fields.get('image','?')}`\n"
        f"- **Source**: `{source_loc or 'unknown'}`\n"
        f"- **Bucket**: `{fields.get('bucket','')}`\n"
        f"- **Fix**: _TODO_\n"
    )
    with open(FIXES_MD, "a", encoding="utf-8") as f:
        f.write(entry)


# ── git diff helper ───────────────────────────────────────────────────────────

def _git_changed_files() -> list[str]:
    try:
        result = _run_hidden(
            ["git", "-C", str(ROOT), "diff", "--name-only", "HEAD"],
            capture_output=True, text=True, timeout=5)
        files = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        # also staged
        result2 = _run_hidden(
            ["git", "-C", str(ROOT), "diff", "--cached", "--name-only"],
            capture_output=True, text=True, timeout=5)
        files += [l.strip() for l in result2.stdout.splitlines() if l.strip()]
        return list(dict.fromkeys(files))  # dedupe, preserve order
    except Exception:
        return []


# ── log line classifier ───────────────────────────────────────────────────────

def _classify_log_line(line: str) -> str:
    m = re.search(r'\[([A-Z][A-Z0-9_]+)\]', line)
    if m:
        tag = m.group(1)
        for key, color in LOG_TAG_COLORS.items():
            if key in tag:
                return color
    lo = line.lower()
    if any(x in lo for x in ("failed", "error", "bsod", "crash", "fatal")):
        return RED
    if "!!!" in line:
        return YELLOW
    return FG_DIM


def _extract_stack_trace(cdb_output: str) -> list[str]:
    """Extract kP 30 stack frames from cdb output into clean list."""
    frames = []
    in_stack = False
    for line in cdb_output.splitlines():
        if re.search(r'Child-SP|RetAddr|Call Site', line, re.IGNORECASE):
            in_stack = True
            continue
        if in_stack:
            # frame lines look like: "fffff804`xxx fffff804`xxx dayzdriv!VmxHandleExit+0x42"
            m = re.match(r'\s*[\da-fA-F`]+\s+[\da-fA-F`]+\s+(.+)', line)
            if m:
                frames.append(m.group(1).strip())
            elif line.strip() == "" and frames:
                break
    return frames[:20]


def _find_matching_crash(fields: dict) -> dict | None:
    """Return previous crash entry with same bugcheck+symbol, or None."""
    bugcheck = fields.get("bugcheck", "").lower()
    symbol   = fields.get("symbol",   "").lower()
    if not bugcheck and not symbol:
        return None
    history = _load_crash_history()
    # search newest-first, skip the last entry (current one being saved)
    for entry in reversed(history[:-1]):
        if (entry.get("bugcheck", "").lower() == bugcheck and
                entry.get("symbol", "").lower() == symbol):
            return entry
    return None


def _get_changed_src_files() -> list[Path]:
    """Return src files modified since dayzdriv.sys was last built."""
    if not BIN.exists():
        return []
    bin_mtime = BIN.stat().st_mtime
    changed = []
    for p in SRC_DIR.iterdir():
        if p.suffix in (".c", ".asm", ".h") and p.stat().st_mtime > bin_mtime:
            changed.append(p)
    return changed


def _build_incremental_cmd(changed: list[Path]) -> list[str] | None:
    """
    Return a cmd.exe /c command string for incremental compile+relink,
    or None if we can't do incremental (e.g. headers changed or too many files).
    Only handles single .c or .asm changes — headers always trigger full rebuild.
    """
    c_files  = [f for f in changed if f.suffix == ".c"]
    asm_files = [f for f in changed if f.suffix == ".asm"]
    h_files  = [f for f in changed if f.suffix == ".h"]

    if h_files or len(changed) > 3:
        return None  # fall back to full rebuild

    msvc    = r"G:\VS2022BT\VC\Tools\MSVC\14.38.33130\bin\HostX64\x64"
    wdk     = r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
    wdklib  = r"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0"
    obj     = str(ROOT / "bin" / "obj")
    out     = str(BIN)
    pdb_out = str(PDB)
    signtool= r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
    clflags = "/kernel /GS- /c /Zi /nologo /W3 /WX- /O2 /Oi /GF /Gy /D _AMD64_"
    incs    = (f'/I "{wdk}\\km" /I "{wdk}\\km\\crt" /I "{wdk}\\shared" '
               f'/I "{wdk}\\ucrt" /I "G:\\VS2022BT\\VC\\Tools\\MSVC\\14.38.33130\\include"')

    steps = ["@echo off"]
    for f in c_files:
        obj_name = f.stem + ".obj"
        steps.append(
            f'"{msvc}\\cl.exe" {clflags} {incs} '
            f'/Fo"{obj}\\{obj_name}" "{f}"'
        )
        steps.append(f'if %errorlevel% neq 0 ( echo FAILED: cl {f.name} & exit /b 1 )')
    for f in asm_files:
        steps.append(
            f'"{msvc}\\ml64.exe" /c /Fo "{obj}\\vcasm.obj" "{f}"'
        )
        steps.append(f'if %errorlevel% neq 0 ( echo FAILED: ml64 & exit /b 1 )')

    all_objs = " ".join(
        f'"{obj}\\{n}"' for n in
        ["Driver.obj", "Vmx.obj", "Ept.obj", "Loader.obj", "vcasm.obj"])
    steps.append(
        f'"{msvc}\\link.exe" /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:DriverEntry '
        f'/INCREMENTAL:NO /NODEFAULTLIB /RELEASE /DEBUG /PDB:"{pdb_out}" /OUT:"{out}" '
        f'{all_objs} '
        f'"{wdklib}\\km\\x64\\ntoskrnl.lib" "{wdklib}\\km\\x64\\hal.lib" '
        f'"{wdklib}\\km\\x64\\BufferOverflowK.lib"'
    )
    steps.append(f'if %errorlevel% neq 0 ( echo FAILED: link & exit /b 1 )')
    steps.append(
        f'"{signtool}" sign /v /fd sha256 /s PrivateCertStore /n DayZTestCert '
        f'/t http://timestamp.digicert.com/shield/timestamp "{out}"'
    )
    steps.append(f'if %errorlevel% neq 0 ( echo FAILED: signtool & exit /b 1 )')
    steps.append("echo BUILD OK")
    return ["cmd.exe", "/c", " & ".join(steps)]


def _run_preload_checklist() -> tuple[bool, list[tuple[str, bool, str]]]:
    """
    Run pre-load checks. Returns (all_ok, [(label, ok, detail), ...]).
    """
    checks = []

    # 1. driver binary exists
    ok = BIN.exists()
    checks.append(("dayzdriv.sys built", ok, str(BIN) if ok else "not found"))

    # 2. binary is signed (signtool verify)
    signed = False
    sig_detail = "signtool not found"
    signtool = Path(r"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe")
    if signtool.exists() and BIN.exists():
        try:
            r = _run_hidden([str(signtool), "verify", "/pa", str(BIN)],
                            capture_output=True, text=True, timeout=10)
            signed = r.returncode == 0
            sig_detail = "signature valid" if signed else r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "invalid"
        except Exception as e:
            sig_detail = str(e)
    checks.append(("Binary signed", signed, sig_detail))

    # 3. kdmapper exists
    ok = KDMAPPER.exists()
    checks.append(("kdmapper found", ok, str(KDMAPPER) if ok else "not found"))

    # 4. no existing dayz service
    try:
        r = _run_hidden(["sc.exe", "query", "dayz"], capture_output=True, text=True, timeout=5)
        running = r.returncode == 0
        checks.append(("No existing dayz svc", not running,
                        "service already exists — Stop Driver first" if running else "clean"))
    except Exception:
        checks.append(("No existing dayz svc", True, "could not check"))

    # 5. test signing enabled
    try:
        r = _run_hidden(["bcdedit", "/enum", "{current}"],
                        capture_output=True, text=True, timeout=5)
        testsigning = "testsigning" in r.stdout.lower() and "yes" in r.stdout.lower()
        checks.append(("Test signing on", testsigning,
                        "enabled" if testsigning else "DISABLED — run: bcdedit /set testsigning on"))
    except Exception:
        checks.append(("Test signing on", False, "could not check"))

    all_ok = all(ok for _, ok, _ in checks)
    return all_ok, checks


# ─────────────────────────────────────────────────────────────────────────────
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("dayzdriv")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.geometry("1060x740")
        self.minsize(820, 560)

        self._log_tail_active    = False
        self._log_autoscroll     = True
        self._watch_active       = False
        self._active_proc        = None
        self._output_q           = queue.Queue()
        self._crash_watch_active = False
        self._pre_dump_time      = 0.0
        self._prev_bin_size      = BIN.stat().st_size if BIN.exists() else 0
        self._build_start_time   = 0.0
        self._tray_icon          = None
        self._tray_color         = FG_DIM
        self._session_builds     = 0
        self._session_loads      = 0
        self._session_crashes    = 0
        self._crash_tab_idx      = 3  # updated after nb built

        self._build_ui()
        self._apply_ttk_style()
        self._bind_keys()
        self._poll_output()
        self._refresh_status()
        self.after(5000, self._periodic_status)
        self.protocol("WM_DELETE_WINDOW", self._quit_app)
        _session_log("GUI started")

    # ── TTK style ─────────────────────────────────────────────────────────────

    def _apply_ttk_style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TNotebook",     background=BG2, borderwidth=0)
        s.configure("TNotebook.Tab", background=BG3, foreground=FG_DIM,
                    padding=[10, 4], font=LABEL)
        s.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", FG)])
        s.configure("Build.Horizontal.TProgressbar",
                    troughcolor=BG3, background=BLUE, thickness=6)
        s.configure("TSeparator", background=ACCENT)
        for name in ("Crash", "Session"):
            s.configure(f"{name}.Treeview",
                        background=BG, foreground=FG, fieldbackground=BG,
                        rowheight=22, font=MONO)
            s.configure(f"{name}.Treeview.Heading",
                        background=BG3, foreground=FG_DIM, font=LABEL)
            s.map(f"{name}.Treeview", background=[("selected", ACCENT)])

    # ── keyboard shortcuts ────────────────────────────────────────────────────

    def _bind_keys(self):
        self.bind("<F5>",  lambda _: self._do_build_load())
        self.bind("<F6>",  lambda _: self._do_load())
        self.bind("<F7>",  lambda _: self._do_build())
        self.bind("<F8>",  lambda _: self._do_stop())
        self.bind("<Escape>", lambda _: self._escape_pressed())

    def _escape_pressed(self):
        if self._log_tail_active:
            self._stop_tail()
        elif self._watch_active:
            self._toggle_watch()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        # top bar
        top = tk.Frame(self, bg=BG, pady=6, padx=10)
        top.pack(fill="x")
        tk.Label(top, text="dayzdriv", font=("Segoe UI", 13, "bold"),
                 bg=BG, fg=FG).pack(side="left")
        self._status_dot = tk.Label(top, text="●", font=("Segoe UI", 14),
                                    bg=BG, fg=FG_DIM)
        self._status_dot.pack(side="left", padx=(10, 2))
        self._status_lbl = tk.Label(top, text="not loaded", font=LABEL,
                                    bg=BG, fg=FG_DIM)
        self._status_lbl.pack(side="left")
        self._session_lbl = tk.Label(top, text="", font=SMALL, bg=BG, fg=FG_DIM)
        self._session_lbl.pack(side="left", padx=(16, 0))
        self._bin_lbl = tk.Label(top, text="", font=LABEL, bg=BG, fg=FG_DIM)
        self._bin_lbl.pack(side="right", padx=(0, 8))
        ttk.Separator(self, orient="horizontal").pack(fill="x")

        # button row
        row1 = tk.Frame(self, bg=BG2, pady=6, padx=10)
        row1.pack(fill="x")
        self._btn_build     = self._btn(row1, "Build [F7]",       self._do_build,        BLUE)
        self._btn_load      = self._btn(row1, "Load [F6]",        self._do_load,         GREEN)
        self._btn_buildload = self._btn(row1, "Build+Load [F5]",  self._do_build_load,   ORANGE)
        self._btn_stop      = self._btn(row1, "Stop [F8]",        self._do_stop,         RED)
        self._btn_tail      = self._btn(row1, "Tail Log",         self._toggle_tail,     YELLOW)
        self._btn_watch     = self._btn(row1, "Watch src",        self._toggle_watch,    PURPLE)
        self._btn_analyze   = self._btn(row1, "Analyze Dump",     self._do_analyze,      ACCENT)
        self._btn_clear     = self._btn(row1, "Clear",            self._clear_output,    "#555555")
        self._btn_tray      = self._btn(row1, "→ Tray",           self._minimize_to_tray,"#455a64")

        # progress bar (hidden until build)
        self._prog_frame = tk.Frame(self, bg=BG2, padx=10, pady=0)
        self._prog_bar = ttk.Progressbar(self._prog_frame,
                                          style="Build.Horizontal.TProgressbar",
                                          orient="horizontal", mode="determinate",
                                          maximum=BUILD_STEPS, value=0)
        self._prog_lbl = tk.Label(self._prog_frame, text="", font=SMALL,
                                   bg=BG2, fg=FG_DIM, anchor="w")
        self._prog_frame.pack_forget()
        ttk.Separator(self, orient="horizontal").pack(fill="x")

        # paned: left tabs | right dump browser
        paned = tk.PanedWindow(self, orient="horizontal", bg=BG,
                               sashwidth=4, sashrelief="flat")
        paned.pack(fill="both", expand=True)

        left = tk.Frame(paned, bg=BG)
        paned.add(left, minsize=460, stretch="always")

        self._nb = ttk.Notebook(left)
        self._nb.pack(fill="both", expand=True)

        self._out_txt    = self._tab(self._nb, "Output")
        self._drvlog_txt = self._build_drvlog_tab(self._nb)
        self._errlog_txt = self._tab(self._nb, "Error Log")
        self._crash_tab_idx = 3
        self._hist_frame = self._crash_history_tab(self._nb)
        self._sess_frame = self._session_tab(self._nb)
        self._diff_frame = self._diff_tab(self._nb)

        # filter + autoscroll bar (below notebook)
        filter_bar = tk.Frame(left, bg=BG2, pady=3, padx=6)
        filter_bar.pack(fill="x", side="bottom")
        tk.Label(filter_bar, text="Filter:", font=SMALL, bg=BG2, fg=FG_DIM).pack(side="left")
        self._filter_var = tk.StringVar()
        self._filter_var.trace_add("write", self._apply_log_filter)
        tk.Entry(filter_bar, textvariable=self._filter_var,
                 font=MONO, bg=BG3, fg=FG, insertbackground=FG,
                 relief="flat", width=22).pack(side="left", padx=(4, 0))
        tk.Button(filter_bar, text="✕", font=SMALL, bg=BG2, fg=FG_DIM,
                  relief="flat", cursor="hand2",
                  command=lambda: self._filter_var.set("")).pack(side="left", padx=2)

        # autoscroll toggle
        self._autoscroll_var = tk.BooleanVar(value=True)
        tk.Checkbutton(filter_bar, text="Auto-scroll", variable=self._autoscroll_var,
                       font=SMALL, bg=BG2, fg=FG_DIM, selectcolor=BG3,
                       activebackground=BG2, activeforeground=FG,
                       command=self._on_autoscroll_toggle).pack(side="right", padx=6)

        # right: dump browser
        right = tk.Frame(paned, bg=BG2, width=230)
        paned.add(right, minsize=180, stretch="never")
        self._build_dump_browser(right)

        # status bar
        bar = tk.Frame(self, bg=ACCENT, pady=2, padx=8)
        bar.pack(fill="x", side="bottom")
        self._bar_lbl = tk.Label(bar, text="Ready  |  F5=Build+Load  F6=Load  F7=Build  F8=Stop  Esc=stop tail/watch",
                                  font=LABEL, bg=ACCENT, fg=FG, anchor="w")
        self._bar_lbl.pack(side="left", fill="x", expand=True)
        self._crash_lbl = tk.Label(bar, text="", font=LABEL, bg=ACCENT, fg=YELLOW)
        self._crash_lbl.pack(side="right")

    def _btn(self, parent, text, cmd, color):
        b = tk.Button(parent, text=text, command=cmd, font=BOLD,
                      bg=color, fg="white", relief="flat", padx=9, pady=4,
                      activebackground=color, activeforeground="white", cursor="hand2")
        b.pack(side="left", padx=3)
        return b

    def _tab(self, nb, title) -> scrolledtext.ScrolledText:
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text=f"  {title}  ")
        txt = scrolledtext.ScrolledText(frame, font=MONO, bg=BG, fg=FG,
                                         insertbackground=FG, relief="flat",
                                         wrap="word", state="disabled",
                                         selectbackground=ACCENT)
        txt.pack(fill="both", expand=True)
        for tag, color in (("ok", GREEN), ("err", RED), ("warn", YELLOW),
                           ("dim", FG_DIM), ("info", BLUE), ("src", ORANGE)):
            txt.tag_config(tag, foreground=color)
        txt.tag_config("hi",   background=ACCENT)
        txt.tag_config("link", foreground=BLUE, underline=True)
        return txt

    def _build_drvlog_tab(self, nb) -> scrolledtext.ScrolledText:
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  Driver Log  ")
        txt = scrolledtext.ScrolledText(frame, font=MONO, bg=BG, fg=FG_DIM,
                                         insertbackground=FG, relief="flat",
                                         wrap="word", state="disabled",
                                         selectbackground=ACCENT)
        txt.pack(fill="both", expand=True)
        # tag per log category
        for key, color in LOG_TAG_COLORS.items():
            txt.tag_config(f"log_{key}", foreground=color)
        txt.tag_config("hi", background=ACCENT)
        return txt

    def _crash_history_tab(self, nb) -> tk.Frame:
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  Crash History  ")
        cols = ("time", "dump", "bugcheck", "symbol", "source", "note")
        tree = ttk.Treeview(frame, columns=cols, show="headings",
                             selectmode="browse", style="Crash.Treeview")
        for col, w, lbl in (("time", 125, "Time"), ("dump", 150, "Dump"),
                             ("bugcheck", 80, "Bugcheck"), ("symbol", 165, "Symbol"),
                             ("source", 190, "Source"), ("note", 140, "Note")):
            tree.heading(col, text=lbl)
            tree.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        tree.bind("<Double-1>", self._open_source_from_history)
        self._crash_tree = tree
        self._populate_crash_history()

        bf = tk.Frame(frame, bg=BG2, pady=3, padx=6)
        bf.pack(fill="x")
        tk.Button(bf, text="Open in VS Code", font=SMALL, bg=ACCENT, fg=FG,
                  relief="flat", cursor="hand2",
                  command=self._open_source_from_history).pack(side="left", padx=2)
        tk.Button(bf, text="Append FIXES.md", font=SMALL, bg=BG3, fg=FG_DIM,
                  relief="flat", cursor="hand2",
                  command=self._append_fixes_from_selected).pack(side="left", padx=2)
        tk.Label(bf, text="Note:", font=SMALL, bg=BG2, fg=FG_DIM).pack(side="left", padx=(12, 2))
        self._note_var = tk.StringVar()
        note_entry = tk.Entry(bf, textvariable=self._note_var, font=MONO,
                               bg=BG3, fg=FG, insertbackground=FG, relief="flat", width=28)
        note_entry.pack(side="left")
        note_entry.bind("<Return>", self._save_note)
        tk.Button(bf, text="Save note", font=SMALL, bg=BG3, fg=FG_DIM,
                  relief="flat", cursor="hand2",
                  command=self._save_note).pack(side="left", padx=2)
        tree.bind("<<TreeviewSelect>>", self._on_crash_select)
        return frame

    def _session_tab(self, nb) -> tk.Frame:
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  Session  ")
        cols = ("time", "event", "detail")
        tree = ttk.Treeview(frame, columns=cols, show="headings",
                             selectmode="browse", style="Session.Treeview")
        for col, w, lbl in (("time", 75, "Time"), ("event", 105, "Event"),
                             ("detail", 420, "Detail")):
            tree.heading(col, text=lbl)
            tree.column(col, width=w, anchor="w")
        sb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        tree.pack(fill="both", expand=True)
        self._sess_tree = tree
        # crash timeline canvas
        self._timeline_canvas = tk.Canvas(frame, bg=BG2, height=40,
                                           highlightthickness=0)
        self._timeline_canvas.pack(fill="x", side="bottom")
        self._timeline_events: list[tuple[float, str]] = []  # (epoch, "crash"|"load"|"build")

        bf = tk.Frame(frame, bg=BG2, pady=3, padx=6)
        bf.pack(fill="x", side="bottom")
        self._sess_summary_lbl = tk.Label(bf, text="", font=SMALL, bg=BG2, fg=FG_DIM)
        self._sess_summary_lbl.pack(side="left")
        return frame

    def _diff_tab(self, nb) -> tk.Frame:
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  Diff  ")
        txt = scrolledtext.ScrolledText(frame, font=MONO, bg=BG, fg=FG,
                                         insertbackground=FG, relief="flat",
                                         wrap="none", state="disabled",
                                         selectbackground=ACCENT)
        txt.pack(fill="both", expand=True)
        txt.tag_config("add",    foreground=GREEN)
        txt.tag_config("remove", foreground=RED)
        txt.tag_config("hunk",   foreground=CYAN)
        txt.tag_config("file",   foreground=YELLOW, font=BOLD)
        txt.tag_config("dim",    foreground=FG_DIM)
        self._diff_txt = txt

        bf = tk.Frame(frame, bg=BG2, pady=3, padx=6)
        bf.pack(fill="x", side="bottom")
        tk.Button(bf, text="Refresh diff", font=SMALL, bg=ACCENT, fg=FG,
                  relief="flat", cursor="hand2",
                  command=self._refresh_diff).pack(side="left", padx=2)
        tk.Label(bf, text="git diff HEAD (working tree vs last commit)",
                 font=SMALL, bg=BG2, fg=FG_DIM).pack(side="left", padx=8)
        return frame

    def _refresh_diff(self):
        self._diff_txt.configure(state="normal")
        self._diff_txt.delete("1.0", "end")
        try:
            result = _run_hidden(
                ["git", "-C", str(ROOT), "diff", "HEAD", "--", "src/"],
                capture_output=True, text=True, timeout=10)
            diff = result.stdout
            if not diff.strip():
                self._diff_txt.insert("end", "(no changes vs HEAD in src/)\n", "dim")
            else:
                for line in diff.splitlines(keepends=True):
                    if line.startswith("+++") or line.startswith("---"):
                        tag = "file"
                    elif line.startswith("+"):
                        tag = "add"
                    elif line.startswith("-"):
                        tag = "remove"
                    elif line.startswith("@@"):
                        tag = "hunk"
                    else:
                        tag = "dim"
                    self._diff_txt.insert("end", line, tag)
        except Exception as e:
            self._diff_txt.insert("end", f"git diff failed: {e}\n", "remove")
        self._diff_txt.configure(state="disabled")

    def _build_dump_browser(self, parent):
        tk.Label(parent, text="Dumps", font=BOLD, bg=BG2, fg=FG_DIM,
                 pady=6).pack(fill="x", padx=8)
        frame = tk.Frame(parent, bg=BG2)
        frame.pack(fill="both", expand=True, padx=4)
        sb = ttk.Scrollbar(frame, orient="vertical")
        self._dump_lb = tk.Listbox(frame, bg=BG3, fg=FG, font=SMALL,
                                    selectbackground=ACCENT, relief="flat",
                                    yscrollcommand=sb.set, activestyle="none",
                                    borderwidth=0, highlightthickness=0)
        sb.config(command=self._dump_lb.yview)
        sb.pack(side="right", fill="y")
        self._dump_lb.pack(fill="both", expand=True)
        btn_row = tk.Frame(parent, bg=BG2, pady=4)
        btn_row.pack(fill="x", padx=4)
        tk.Button(btn_row, text="Analyze", font=SMALL, bg=ACCENT, fg=FG,
                  relief="flat", cursor="hand2",
                  command=self._analyze_selected_dump).pack(side="left", padx=2)
        tk.Button(btn_row, text="Refresh", font=SMALL, bg=BG3, fg=FG_DIM,
                  relief="flat", cursor="hand2",
                  command=self._refresh_dump_browser).pack(side="left", padx=2)
        self._refresh_dump_browser()

    # ── dump browser ──────────────────────────────────────────────────────────

    def _refresh_dump_browser(self):
        self._dump_lb.delete(0, "end")
        seen: dict[str, Path] = {}
        for d in (DUMPS_DIR, WIN_DUMPS):
            try:
                for p in d.glob("*.dmp"):
                    if p.name not in seen or d == DUMPS_DIR:
                        seen[p.name] = p
            except Exception:
                pass
        dumps = sorted(seen.values(), key=lambda p: p.stat().st_mtime, reverse=True)
        self._dump_paths = dumps
        for p in dumps:
            mtime = datetime.fromtimestamp(p.stat().st_mtime).strftime("%m-%d %H:%M")
            self._dump_lb.insert("end", f"{mtime}  {p.name}")
        if not dumps:
            self._dump_lb.insert("end", "(none found)")

    def _analyze_selected_dump(self):
        sel = self._dump_lb.curselection()
        if not sel or not getattr(self, "_dump_paths", None):
            return
        idx = sel[0]
        if idx >= len(self._dump_paths):
            return
        dump = self._dump_paths[idx]
        self._out(f"[{ts()}] Analyzing {dump.name}…\n", "info")
        self._nb.select(0)
        threading.Thread(target=self._copy_and_analyze, args=(dump,), daemon=True).start()

    # ── crash history ─────────────────────────────────────────────────────────

    def _populate_crash_history(self):
        self._crash_tree.delete(*self._crash_tree.get_children())
        count = 0
        for entry in reversed(_load_crash_history()):
            self._crash_tree.insert("", "end", values=(
                entry.get("time", ""),
                entry.get("dump", ""),
                entry.get("bugcheck", ""),
                entry.get("symbol", ""),
                entry.get("source", ""),
                entry.get("note", ""),
            ))
            count += 1
        # update tab badge
        tab_text = f"  Crash History ({count})  " if count else "  Crash History  "
        self._nb.tab(self._crash_tab_idx, text=tab_text)

    def _on_crash_select(self, *_):
        sel = self._crash_tree.selection()
        if not sel:
            return
        vals = self._crash_tree.item(sel[0], "values")
        self._note_var.set(vals[5] if len(vals) > 5 else "")

    def _save_note(self, *_):
        sel = self._crash_tree.selection()
        if not sel:
            return
        vals = self._crash_tree.item(sel[0], "values")
        dump_name = vals[1] if len(vals) > 1 else ""
        note = self._note_var.get().strip()
        _update_crash_entry_note(dump_name, note)
        self._populate_crash_history()
        self._bar(f"Note saved for {dump_name}")

    def _open_source_from_history(self, *_):
        sel = self._crash_tree.selection()
        if not sel:
            return
        vals = self._crash_tree.item(sel[0], "values")
        source = vals[4] if len(vals) > 4 else ""
        if not source:
            messagebox.showinfo("No source", "No source location resolved for this crash.")
            return
        self._open_in_vscode(source)

    def _append_fixes_from_selected(self):
        sel = self._crash_tree.selection()
        if not sel:
            return
        vals = self._crash_tree.item(sel[0], "values")
        fields = {"bugcheck": vals[2] if len(vals) > 2 else "",
                  "symbol":   vals[3] if len(vals) > 3 else "",
                  "source":   vals[4] if len(vals) > 4 else ""}
        _append_fixes_entry(fields, fields.get("source"))
        self._out(f"[{ts()}] Appended FIXES.md entry.\n", "ok")
        _session_log("Appended FIXES.md entry")

    # ── session tab ───────────────────────────────────────────────────────────

    def _sess_add(self, event: str, detail: str):
        self._sess_tree.insert("", "end", values=(ts(), event, detail))
        self._sess_tree.yview_moveto(1.0)
        summary = (f"builds={self._session_builds}  "
                   f"loads={self._session_loads}  "
                   f"crashes={self._session_crashes}")
        self._sess_summary_lbl.configure(text=summary)
        self._session_lbl.configure(
            text=f"  B:{self._session_builds} L:{self._session_loads} C:{self._session_crashes}")
        # record on timeline
        kind_map = {"Build": "build", "Load": "load", "Crash": "crash", "Stable": "stable"}
        tl_kind = kind_map.get(event)
        if tl_kind:
            self._timeline_add(tl_kind)

    def _timeline_add(self, kind: str):
        """Record an event on the session timeline and redraw."""
        self._timeline_events.append((time.time(), kind))
        self._redraw_timeline()

    def _redraw_timeline(self):
        c = self._timeline_canvas
        c.delete("all")
        events = self._timeline_events
        if len(events) < 2:
            if events:
                c.create_text(10, 20, text=events[0][1], fill=FG_DIM,
                              anchor="w", font=SMALL)
            return
        w = c.winfo_width() or 400
        h = c.winfo_height() or 40
        t0 = events[0][0]
        t1 = events[-1][0]
        span = max(t1 - t0, 1)
        color_map = {"crash": RED, "load": GREEN, "build": BLUE, "stable": FG_DIM}
        # draw timeline bar
        c.create_rectangle(4, h//2-2, w-4, h//2+2, fill=ACCENT, outline="")
        for epoch, kind in events:
            x = 4 + int((epoch - t0) / span * (w - 8))
            color = color_map.get(kind, FG_DIM)
            c.create_oval(x-5, h//2-5, x+5, h//2+5, fill=color, outline="")
        # legend
        x_leg = 6
        for kind, color in color_map.items():
            c.create_oval(x_leg, h-12, x_leg+8, h-4, fill=color, outline="")
            c.create_text(x_leg+11, h-8, text=kind, fill=FG_DIM,
                          anchor="w", font=SMALL)
            x_leg += 55

    # ── autoscroll toggle ─────────────────────────────────────────────────────

    def _on_autoscroll_toggle(self):
        self._log_autoscroll = self._autoscroll_var.get()

    # ── log filter ────────────────────────────────────────────────────────────

    def _apply_log_filter(self, *_):
        term = self._filter_var.get().strip().lower()
        txt = self._drvlog_txt
        txt.tag_remove("hi", "1.0", "end")
        if not term:
            return
        start = "1.0"
        while True:
            pos = txt.search(term, start, nocase=True, stopindex="end")
            if not pos:
                break
            end = f"{pos}+{len(term)}c"
            txt.tag_add("hi", pos, end)
            start = end

    # ── build progress ────────────────────────────────────────────────────────

    def _show_progress(self, show: bool):
        if show:
            self._prog_bar["value"] = 0
            self._prog_lbl.configure(text="")
            self._prog_bar.pack(fill="x", pady=(2, 2))
            self._prog_lbl.pack(fill="x")
            self._prog_frame.pack(fill="x")
        else:
            self._prog_frame.pack_forget()

    def _update_progress(self, line: str):
        m = re.match(r"\[(\d+)/(\d+)\]\s*(.*)", line.strip())
        if m:
            step, total, label = int(m.group(1)), int(m.group(2)), m.group(3)
            self._prog_bar["maximum"] = total
            self._prog_bar["value"] = step
            self._prog_lbl.configure(text=f"Step {step}/{total}: {label}")

    # ── output helpers ────────────────────────────────────────────────────────

    def _append(self, widget: scrolledtext.ScrolledText, text: str, tag="",
                autoscroll: bool = True):
        widget.configure(state="normal")
        widget.insert("end", text, tag)
        if autoscroll and self._log_autoscroll:
            widget.see("end")
        widget.configure(state="disabled")

    def _out(self, text: str, tag=""):
        self._append(self._out_txt, text, tag)

    def _log(self, text: str, tag=""):
        self._append(self._drvlog_txt, text, tag, autoscroll=self._log_autoscroll)

    def _err(self, text: str):
        self._append(self._errlog_txt, f"[{ts()}] {text}\n", "err")

    def _bar(self, text: str):
        self._bar_lbl.configure(text=text)

    def _clear_output(self):
        for w in (self._out_txt, self._drvlog_txt):
            w.configure(state="normal")
            w.delete("1.0", "end")
            w.configure(state="disabled")
        self._bar("Cleared.")

    def _classify(self, line: str) -> str:
        lo = line.lower()
        if any(x in lo for x in ("failed", "error", "bsod", "crash", "fatal")):
            return "err"
        if any(x in lo for x in ("warning", "warn")):
            return "warn"
        if "build ok" in lo or lo.strip() == "ok":
            return "ok"
        if "!!!" in line:
            return "warn"
        return ""

    # ── status ────────────────────────────────────────────────────────────────

    def _refresh_status(self):
        if BIN.exists():
            mtime = datetime.fromtimestamp(BIN.stat().st_mtime)
            size_kb = BIN.stat().st_size // 1024
            self._bin_lbl.configure(
                text=f"bin: {mtime.strftime('%Y-%m-%d %H:%M')}  {size_kb} KB",
                fg=FG_DIM)
        else:
            self._bin_lbl.configure(text="bin: not built", fg=RED)
        try:
            loaded = DRVLOG.exists() and (time.time() - DRVLOG.stat().st_mtime) < 300
        except Exception:
            loaded = False
        color = GREEN if loaded else FG_DIM
        self._status_dot.configure(fg=color)
        self._status_lbl.configure(text="driver mapped" if loaded else "not loaded", fg=color)
        self._update_tray_color(GREEN if loaded else FG_DIM)

    def _periodic_status(self):
        self._refresh_status()
        self.after(5000, self._periodic_status)

    # ── subprocess runner ─────────────────────────────────────────────────────

    def _run_cmd(self, args, label: str, on_done=None, is_build=False):
        if self._active_proc and self._active_proc.poll() is None:
            self._err("Another process is already running.")
            return
        self._out(f"\n[{ts()}] >>> {label}\n", "info")
        self._bar(f"Running: {label}…")
        if is_build:
            self._show_progress(True)
            self._build_start_time = time.time()

        def _worker():
            try:
                proc = subprocess.Popen(
                    args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, startupinfo=_si(),
                    creationflags=subprocess.CREATE_NO_WINDOW)
                self._active_proc = proc
                for line in proc.stdout:
                    self._output_q.put(("out", line, None, is_build))
                proc.wait()
                code = proc.returncode
                self._output_q.put(("out", f"[{ts()}] exit={code}\n",
                                    "ok" if code == 0 else "err", False))
                self._output_q.put(("done", code, on_done))
            except Exception as exc:
                self._output_q.put(("out", f"[{ts()}] ERROR: {exc}\n", "err", False))
                self._output_q.put(("done", -1, on_done))

        threading.Thread(target=_worker, daemon=True).start()

    def _poll_output(self):
        try:
            while True:
                item = self._output_q.get_nowait()
                kind = item[0]
                if kind == "out":
                    _, text, tag, is_build = item
                    if tag is None:
                        tag = self._classify(text)
                    self._out(text, tag)
                    if is_build:
                        self._update_progress(text)
                elif kind == "log":
                    line, color = item[1], item[2]
                    self._drvlog_txt.configure(state="normal")
                    self._drvlog_txt.insert("end", line, ("logline",))
                    # apply per-char color via tag
                    self._drvlog_txt.tag_config("logline", foreground=color)
                    if self._log_autoscroll:
                        self._drvlog_txt.see("end")
                    self._drvlog_txt.configure(state="disabled")
                    self._apply_log_filter()
                elif kind == "done":
                    _, code, cb = item
                    self._bar(f"Done (exit={code})")
                    self._show_progress(False)
                    self._refresh_status()
                    if cb:
                        cb(code)
                elif kind == "crash_done":
                    self._crash_watch_active = False
                    self._crash_lbl.configure(text="")
                    self._update_tray_color(FG_DIM)
                elif kind == "crash_summary":
                    _, dump_name, fields, source_loc, from_watch = item
                    self._show_crash_summary(dump_name, fields, source_loc, from_watch)
                elif kind == "refresh_history":
                    self._populate_crash_history()
                elif kind == "refresh_dumps":
                    self._refresh_dump_browser()
                elif kind == "sess":
                    _, event, detail = item
                    self._sess_add(event, detail)
                elif kind == "repeat_crash":
                    _, prev = item
                    self._on_repeat_crash(prev)
                elif kind == "auto_build":
                    self._do_build()
        except queue.Empty:
            pass
        self.after(80, self._poll_output)

    # ── actions ───────────────────────────────────────────────────────────────

    def _do_build(self, then_load: bool = False):
        self._session_builds += 1
        _session_log("Build started")
        self._output_q.put(("sess", "Build", "started"))
        cb = (lambda code: self._after_build(code, then_load=True)) if then_load else self._after_build

        changed = _get_changed_src_files()
        inc_cmd = _build_incremental_cmd(changed) if changed else None
        if inc_cmd and changed:
            names = ", ".join(f.name for f in changed)
            self._out(f"[{ts()}] Incremental build: {names}\n", "info")
            self._run_cmd(inc_cmd, f"incremental ({names})", on_done=cb, is_build=True)
        else:
            self._run_cmd(["cmd.exe", "/c", str(REBUILD_BAT)],
                          "rebuild.bat", on_done=cb, is_build=True)

    def _after_build(self, code: int, then_load: bool = False):
        elapsed = time.time() - self._build_start_time
        elapsed_s = f"{elapsed:.1f}s"
        if code == 0:
            new_size = BIN.stat().st_size if BIN.exists() else 0
            delta = new_size - self._prev_bin_size
            sign = "+" if delta >= 0 else ""
            size_msg = f"{new_size // 1024} KB ({sign}{delta} bytes)"
            self._out(f"[{ts()}] Build OK — {size_msg}  [{elapsed_s}]\n", "ok")
            self._prev_bin_size = new_size

            # show git diff of changed files
            changed = _git_changed_files()
            if changed:
                self._out(f"[{ts()}] Changed files: {', '.join(changed)}\n", "info")
            else:
                self._out(f"[{ts()}] No uncommitted changes in git.\n", "dim")

            _session_log(f"Build OK — {size_msg} in {elapsed_s}")
            self._output_q.put(("sess", "Build", f"OK {size_msg} [{elapsed_s}]"))
            self._refresh_diff()
            if then_load:
                self._do_load()
        else:
            self._out(f"[{ts()}] Build FAILED [{elapsed_s}]\n", "err")
            self._err(f"Build failed (exit={code}) in {elapsed_s}")
            self._nb.select(2)
            _session_log(f"Build FAILED exit={code} in {elapsed_s}")
            self._output_q.put(("sess", "Build", f"FAILED exit={code} [{elapsed_s}]"))

    def _do_load(self):
        all_ok, checks = _run_preload_checklist()
        sep = "-" * 48
        self._out(f"\n{sep}\n  PRE-LOAD CHECKLIST\n{sep}\n", "info")
        for label, ok, detail in checks:
            icon = "✓" if ok else "✗"
            tag  = "ok" if ok else "err"
            self._out(f"  {icon} {label:<28} {detail}\n", tag)
        self._out(f"{sep}\n\n", "info")
        if not all_ok:
            self._out(f"[{ts()}] Pre-load checks failed — aborting.\n", "err")
            self._err("Pre-load checklist failed — see Output tab.")
            return
        self._session_loads += 1
        self._pre_dump_time = self._latest_dump_mtime(WIN_DUMPS)
        _session_log("kdmapper load")
        self._output_q.put(("sess", "Load", "kdmapper started"))
        self._run_cmd([str(KDMAPPER), str(BIN)], "kdmapper load",
                      on_done=self._after_load)

    def _do_build_load(self):
        self._do_build(then_load=True)

    def _after_load(self, code: int):
        if code != 0:
            self._out(f"[{ts()}] kdmapper FAILED (exit={code})\n", "err")
            self._err(f"kdmapper returned {code}")
            _session_log(f"Load FAILED exit={code}")
            self._output_q.put(("sess", "Load", f"FAILED exit={code}"))
            return
        self._out(f"[{ts()}] Driver mapped OK — watching 30s for crash…\n", "ok")
        self._bar("Watching for crash dump…")
        self._crash_lbl.configure(text="crash watch active")
        self._crash_watch_active = True
        self._update_tray_color(YELLOW)
        _session_log("Driver mapped OK")
        self._output_q.put(("sess", "Load", "mapped OK — watching"))
        threading.Thread(target=self._watch_crash, daemon=True).start()
        if not self._log_tail_active:
            self._start_tail()

    def _watch_crash(self):
        deadline = time.time() + 30
        pre = self._pre_dump_time
        while time.time() < deadline:
            time.sleep(2)
            found = self._newest_dump_after(WIN_DUMPS, pre)
            if found:
                self._session_crashes += 1
                self._output_q.put(("out", f"\n[{ts()}] CRASH: {found.name}\n", "err", False))
                self._output_q.put(("sess", "Crash", found.name))
                self._update_tray_color(RED)
                self._tray_flash()
                self._copy_and_analyze(found, from_crash_watch=True)
                self._output_q.put(("crash_done",))
                return
        self._output_q.put(("out", f"[{ts()}] No crash in 30s — stable.\n", "ok", False))
        self._output_q.put(("sess", "Stable", "no crash in 30s"))
        self._output_q.put(("crash_done",))

    def _copy_and_analyze(self, dump: Path, from_crash_watch: bool = False):
        DUMPS_DIR.mkdir(exist_ok=True)
        dest = DUMPS_DIR / dump.name
        copied = False
        for _ in range(8):
            try:
                shutil.copy2(dump, dest)
                self._output_q.put(("out", f"[{ts()}] Copied → {dest}\n", "dim", False))
                copied = True
                break
            except PermissionError:
                time.sleep(2)
            except Exception as e:
                self._output_q.put(("out", f"[{ts()}] Copy failed: {e}\n", "warn", False))
                break
        if not copied:
            dest = dump

        cdb_output = ""
        if CDB.exists():
            cmd = [str(CDB), "-z", str(dest), "-y", SYMPATH, "-lines",
                   "-c", "!analyze -v; .bugcheck; kP 30; q"]
            self._output_q.put(("out", f"[{ts()}] cdb !analyze -v…\n", "info", False))
            try:
                result = _run_hidden(cmd, capture_output=True, text=True, timeout=120)
                cdb_output = result.stdout + result.stderr
                for line in cdb_output.splitlines():
                    self._output_q.put(("out", line + "\n", self._classify(line), False))
            except Exception as e:
                self._output_q.put(("out", f"[{ts()}] cdb failed: {e}\n", "err", False))
        else:
            self._output_q.put(("out", f"[{ts()}] cdb not found.\n", "warn", False))

        fields = _extract_crash_fields(cdb_output)
        stack_frames = _extract_stack_trace(cdb_output)
        fields["_stack"] = stack_frames
        source_loc = None
        if fields.get("offset"):
            source_loc = _resolve_offset_to_source(fields["offset"])
            if source_loc:
                self._output_q.put(("out", f"[{ts()}] Source: {source_loc}\n", "src", False))
                fields["source"] = source_loc

        self._output_q.put(("crash_summary", dest.name, fields, source_loc, from_crash_watch))
        entry = {"time": datetime.now().isoformat(timespec="seconds"),
                 "dump": dest.name, **fields}
        _save_crash_entry(entry)
        match = _find_matching_crash(fields)
        if match:
            self._output_q.put(("repeat_crash", match))
        _session_log(f"Analyzed {dest.name}: {fields.get('symbol','?')} @ {source_loc or '?'}")
        self._output_q.put(("refresh_history",))
        self._output_q.put(("refresh_dumps",))

    def _show_crash_summary(self, dump_name: str, fields: dict,
                             source_loc: str | None, popup: bool):
        sep = "=" * 58
        self._out(f"\n{sep}\n", "err")
        self._out(f"  CRASH SUMMARY — {dump_name}\n", "err")
        self._out(f"{sep}\n", "err")
        label_keys = [("Bugcheck", "bugcheck"), ("Symbol", "symbol"),
                      ("Image", "image"), ("Bucket", "bucket"), ("Faulting", "faulting")]
        any_found = False
        for label, key in label_keys:
            val = fields.get(key)
            if val:
                if key == "bugcheck":
                    desc = BUGCHECK_DESCRIPTIONS.get(val.lower(), "")
                    suffix = f"  ({desc})" if desc else ""
                    self._out(f"  {label:<10} {val}{suffix}\n", "warn")
                else:
                    self._out(f"  {label:<10} {val}\n", "warn")
                any_found = True
        if source_loc:
            self._out(f"  {'Source':<10} {source_loc}\n", "src")
            any_found = True
        if not any_found:
            self._out("  (no key fields extracted — see raw output above)\n", "dim")

        # stack trace
        stack_frames = fields.get("_stack", [])
        if stack_frames:
            self._out(f"  {'Stack':<10}\n", "info")
            for i, frame in enumerate(stack_frames):
                self._out(f"    #{i:<2} {frame}\n", "dim")
            self._out("\n", "")

        self._out(f"{sep}\n\n", "err")

        if source_loc:
            self._out_txt.configure(state="normal")
            self._out_txt.insert("end", f"  → Open in VS Code: {source_loc}\n", "link")
            start_idx = self._out_txt.index("end-2l")
            self._out_txt.tag_add("link", start_idx, "end-1c")
            self._out_txt.tag_bind("link", "<Button-1>",
                                   lambda _e, loc=source_loc: self._open_in_vscode(loc))
            self._out_txt.tag_bind("link", "<Enter>",
                                   lambda _e: self._out_txt.configure(cursor="hand2"))
            self._out_txt.tag_bind("link", "<Leave>",
                                   lambda _e: self._out_txt.configure(cursor=""))
            self._out_txt.configure(state="disabled")

        if popup:
            lines = [f"{lbl}: {fields[k]}" for lbl, k in label_keys if fields.get(k)]
            if source_loc:
                lines.append(f"Source: {source_loc}")
            messagebox.showerror(f"CRASH — {dump_name}",
                                 "\n".join(lines) or "No key fields extracted.")
        if popup and any_found:
            _append_fixes_entry(fields, source_loc)
            self._out(f"[{ts()}] FIXES.md entry appended.\n", "dim")

    def _open_in_vscode(self, loc: str):
        if not VSCODE.exists():
            messagebox.showinfo("VS Code not found", f"Expected:\n{VSCODE}")
            return
        try:
            parts = loc.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                path, line = parts
                args = ["cmd.exe", "/c", str(VSCODE), "--goto", f"{path}:{line}"]
            else:
                args = ["cmd.exe", "/c", str(VSCODE), loc]
            subprocess.Popen(args, startupinfo=_si(),
                             creationflags=subprocess.CREATE_NO_WINDOW)
            self._bar(f"Opened {loc} in VS Code")
        except Exception as e:
            self._err(f"VS Code open failed: {e}")

    def _on_repeat_crash(self, prev: dict):
        prev_time = prev.get("time", "?")
        symbol = prev.get("symbol", "?")
        self._out(
            f"\n  ⚠ REPEAT CRASH — same as {symbol} @ {prev_time}\n"
            f"  This is the same root cause as a previous crash.\n"
            f"  Previous note: {prev.get('note', '(none)')}\n\n",
            "warn")
        self._sess_add("Repeat", f"{symbol} — same as {prev_time}")

    def _do_stop(self):
        def _worker():
            for args in (["sc.exe", "stop", "dayz"], ["sc.exe", "delete", "dayz"]):
                try:
                    r = _run_hidden(args, capture_output=True, text=True)
                    self._output_q.put(("out",
                        f"[{ts()}] {' '.join(args)} → exit={r.returncode}\n", "dim", False))
                except Exception as e:
                    self._output_q.put(("out", f"[{ts()}] {args[1]} error: {e}\n", "err", False))
                time.sleep(1)
            self._output_q.put(("done", 0, None))
            self._output_q.put(("sess", "Stop", "sc stop+delete sent"))
        threading.Thread(target=_worker, daemon=True).start()

    def _do_analyze(self):
        dumps = sorted(DUMPS_DIR.glob("*.dmp"),
                       key=lambda p: p.stat().st_mtime) if DUMPS_DIR.exists() else []
        if not dumps:
            try:
                dumps = sorted(WIN_DUMPS.glob("*.dmp"), key=lambda p: p.stat().st_mtime)
            except Exception:
                dumps = []
        if not dumps:
            messagebox.showinfo("No dumps", "No .dmp files found.")
            return
        dump = dumps[-1]
        self._out(f"[{ts()}] Analyzing {dump.name}…\n", "info")
        self._nb.select(0)
        threading.Thread(target=self._copy_and_analyze, args=(dump,), daemon=True).start()

    # ── source watcher ────────────────────────────────────────────────────────

    def _toggle_watch(self):
        if self._watch_active:
            self._watch_active = False
            self._btn_watch.configure(text="Watch src", bg=PURPLE)
            self._bar("Source watch stopped.")
            _session_log("Source watch stopped")
        else:
            self._watch_active = True
            self._btn_watch.configure(text="Stop Watch", bg=RED)
            self._bar("Watching src/ — auto-rebuild on save.  Esc to stop.")
            _session_log("Source watch started")
            threading.Thread(target=self._src_watch_worker, daemon=True).start()

    def _src_watch_worker(self):
        src_files = (list(SRC_DIR.glob("*.c")) + list(SRC_DIR.glob("*.asm")) +
                     list(SRC_DIR.glob("*.h")))
        mtimes = {f: f.stat().st_mtime for f in src_files if f.exists()}
        self._output_q.put(("out",
            f"[{ts()}] Watching {len(mtimes)} files in {SRC_DIR}\n", "info", False))
        while self._watch_active:
            time.sleep(1)
            for f in src_files:
                try:
                    mtime = f.stat().st_mtime
                    if mtime != mtimes.get(f, mtime):
                        mtimes[f] = mtime
                        self._output_q.put(("out",
                            f"[{ts()}] Changed: {f.name} — rebuilding…\n", "warn", False))
                        self._output_q.put(("sess", "Watch", f"{f.name} → rebuild"))
                        _session_log(f"Auto-rebuild: {f.name}")
                        self._output_q.put(("auto_build",))
                        time.sleep(3)
                        break
                except Exception:
                    pass

    # ── log tail ──────────────────────────────────────────────────────────────

    def _toggle_tail(self):
        if self._log_tail_active:
            self._stop_tail()
        else:
            self._start_tail()

    def _start_tail(self):
        self._log_tail_active = True
        self._btn_tail.configure(text="Stop Tail", bg=RED)
        self._nb.select(1)
        self._append(self._drvlog_txt,
                     f"\n[{ts()}] --- tailing {DRVLOG} ---\n", "dim")
        threading.Thread(target=self._tail_worker, daemon=True).start()

    def _stop_tail(self):
        self._log_tail_active = False
        self._btn_tail.configure(text="Tail Log", bg=YELLOW)

    def _tail_worker(self):
        pos = 0
        if DRVLOG.exists():
            with open(DRVLOG, "r", errors="replace") as f:
                f.seek(0, 2)
                pos = f.tell()
        while self._log_tail_active:
            try:
                if DRVLOG.exists():
                    with open(DRVLOG, "r", errors="replace") as f:
                        f.seek(pos)
                        chunk = f.read()
                        if chunk:
                            pos = f.tell()
                            for line in chunk.splitlines(keepends=True):
                                color = _classify_log_line(line)
                                self._output_q.put(("log", line, color))
            except Exception as e:
                self._output_q.put(("log", f"[tail error: {e}]\n", RED))
            time.sleep(0.4)

    # ── system tray ───────────────────────────────────────────────────────────

    def _make_tray(self, color: str) -> pystray.Icon:
        menu = pystray.Menu(
            pystray.MenuItem("Show", self._restore_from_tray, default=True),
            pystray.MenuItem("Quit", self._quit_app),
        )
        return pystray.Icon("dayzdriv", _make_tray_icon(color), "dayzdriv", menu)

    def _minimize_to_tray(self):
        self.withdraw()
        if self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
        self._tray_icon = self._make_tray(self._tray_color)
        threading.Thread(target=self._tray_icon.run, daemon=True).start()

    def _restore_from_tray(self, *_):
        if self._tray_icon:
            self._tray_icon.stop()
            self._tray_icon = None
        self.after(0, self.deiconify)

    def _update_tray_color(self, color: str):
        self._tray_color = color
        if self._tray_icon:
            try:
                self._tray_icon.icon = _make_tray_icon(color)
            except Exception:
                pass

    def _tray_flash(self):
        if not self._tray_icon:
            return
        def _flash():
            for _ in range(6):
                try:
                    self._tray_icon.icon = _make_tray_icon(RED)
                    time.sleep(0.4)
                    self._tray_icon.icon = _make_tray_icon(FG_DIM)
                    time.sleep(0.4)
                except Exception:
                    break
        threading.Thread(target=_flash, daemon=True).start()

    def _quit_app(self, *_):
        _session_log("GUI closed")
        if self._tray_icon:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
        self.destroy()

    # ── dump helpers ──────────────────────────────────────────────────────────

    def _latest_dump_mtime(self, directory: Path) -> float:
        try:
            dumps = list(directory.glob("*.dmp"))
            return max(p.stat().st_mtime for p in dumps) if dumps else 0.0
        except Exception:
            return 0.0

    def _newest_dump_after(self, directory: Path, pre_mtime: float) -> Path | None:
        try:
            for p in sorted(directory.glob("*.dmp"), key=lambda x: x.stat().st_mtime):
                if p.stat().st_mtime > pre_mtime:
                    return p
        except Exception:
            pass
        return None


# ── entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, __file__, None, 1)
        sys.exit()
    app = App()
    app.mainloop()
