#!/bin/bash
# Open a remediation batch in its own Chrome window, then start the sorter.
#
# Asks whether you are on the NCC capacity dashboard or a FiberMan report
# sheet. NCC reads the live down-link charts and opens the links for the
# data hall and discipline you name. A report sheet lists the pages in the
# workbook. It then uses the NCC hyperlinks in the column headed ncc, for
# the page, location, and discipline you pick.
# Nothing is opened until you confirm the count. The new tabs go in a new
# window. The existing Network Command Center window is left alone.
# Those new tabs are sorted by NA/NB row. You can then switch that same
# range to rack triplet, and back, until you type done.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Cristian8281/sort-as-t1-tabs/main/remediate-links.sh | bash
#
# Help:
#   curl -fsSL https://raw.githubusercontent.com/Cristian8281/sort-as-t1-tabs/main/remediate-links.sh | bash -s -- --help
#
# Every question shows numbered choices and a [default]. Type the number or
# the name, press Enter for the default, or q to quit. Ctrl-C cancels.
# Color turns off when output is not a terminal, NO_COLOR is set, or
# TERM=dumb.
#
# Requires macOS, Google Chrome, and the logins already in that Chrome
# profile. Run it in Terminal. It reads answers from the terminal, not from
# the pipe.
set -euo pipefail

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-dumb}" != "dumb" ]; then
  case "${COLORTERM:-}" in
    truecolor|24bit) A=$'\033[38;2;0;170;255m'; W=$'\033[1;38;2;245;247;250m'; D=$'\033[38;2;120;124;132m' ;;
    *)
      case "${TERM:-}" in
        *256*) A=$'\033[38;5;39m'; W=$'\033[1;38;5;255m'; D=$'\033[38;5;244m' ;;
        *) A=$'\033[94m'; W=$'\033[1;97m'; D=$'\033[90m' ;;
      esac ;;
  esac
  B=$'\033[1m'; R=$'\033[91m'; N=$'\033[0m'
  case "${LC_ALL:-${LC_CTYPE:-${LANG:-}}}" in
    *UTF-8*|*utf-8*|*UTF8*|*utf8*) X='✗'; S='╱╱╱'; L='─────────────────────────────────────────────────' ;;
    *) X='[x]'; S='///'; L='-------------------------------------------------' ;;
  esac
else
  A=''; W=''; D=''; B=''; R=''; N=''; X='[x]'; S='///'; L='-------------------------------------------------'
fi
C="$A"

for arg in "$@"; do
  case "$arg" in
    -h|--help)
      cat << HELP

  ${A}${S}${N} ${W}x${A}AI${N} ${W}remediate-links${N}  ${D}NCC / FiberMan -> Chrome -> sorter${N}
  ${D}${L}${N}
  Open one remediation batch in a new Chrome window, then sort it.

${A}${B}Usage${N}
  curl -fsSL https://raw.githubusercontent.com/Cristian8281/sort-as-t1-tabs/main/remediate-links.sh | bash
  curl -fsSL .../remediate-links.sh | bash -s -- --help     ${D}show this help${N}

${A}${B}What happens${N}
  1. Pick a source: the NCC capacity dashboard, or a FiberMan report sheet.
  2. NCC: it reads the live down-link charts (threshold 0.500%).
     Sheet: paste the Google Sheet link and pick a page.
  3. Pick the discipline / link type and the data hall, supercore, spine or location.
  4. Check the summary (count, first and last link) and confirm.
     ${B}Nothing is opened until you confirm.${N}
  5. The links open in a ${B}new${N} Chrome window and the sorter starts
     (NA/NB row first; switch to rack triplet and back, type done to finish).

${A}${B}Answering questions${N}
  Type the number or the name (any case). Enter takes the [default].
  q quits. Ctrl-C cancels at any time.

${A}${B}Requirements${N}
  macOS, Google Chrome running and signed in to the capacity dashboard and
  Google. Run it in Terminal: answers are read from the terminal, not the pipe.

${A}${B}Environment${N}
  NO_COLOR=1           turn off color and Unicode art
  TERM=dumb            plain output, no spinner
  REMEDIATE_NO_ANIM=1  show the banner instantly (no reveal)
HELP
      exit 0
      ;;
  esac
done

if [ "$(uname -s)" != "Darwin" ]; then
  echo "${R}${X} This only runs on macOS, because it opens Google Chrome tabs.${N}" >&2
  echo "  ${D}Run it in Terminal on your Mac. Nothing was opened.${N}" >&2
  exit 1
fi

if ! command -v python3 > /dev/null 2>&1; then
  echo "${R}${X} python3 was not found.${N}" >&2
  echo "  ${D}Install the Command Line Tools with: ${C}xcode-select --install${N}${D}, then run this again. Nothing was opened.${N}" >&2
  exit 1
fi

exec python3 - "$@" << 'PY'
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import quote, unquote
from xml.etree import ElementTree as ET
import sys
import threading

# ---------------------------------------------------------------------------
# Terminal UI helpers. Everything below this block until "Data and Chrome"
# only changes how things look and how answers are asked for.
# ---------------------------------------------------------------------------

TOTAL_STEPS = 5
MAX_TRIES = 5
QUIT_WORDS = {"q", "quit", "exit"}
OPENED = False  # set once tabs start opening, so messages stay truthful
ANSI_RE = re.compile(r"\033\[[0-9;]*[A-Za-z]")


def _fancy(stream):
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM", "dumb") == "dumb":
        return False
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return False


def _utf8():
    loc = os.environ.get("LC_ALL") or os.environ.get("LC_CTYPE") or os.environ.get("LANG") or ""
    if loc:
        return "utf-8" in loc.lower() or "utf8" in loc.lower()
    return "utf" in (getattr(sys.stdout, "encoding", "") or "").lower()


def _depth():
    if os.environ.get("COLORTERM", "").lower() in {"truecolor", "24bit"}:
        return 24
    if "256" in os.environ.get("TERM", ""):
        return 256
    return 16


def _animated():
    try:
        return sys.stdout.isatty() and os.environ.get("TERM", "dumb") != "dumb"
    except (AttributeError, ValueError):
        return False


def _motion():
    """Banner reveal: only on a real terminal, and never with REMEDIATE_NO_ANIM=1."""
    return _animated() and not os.environ.get("REMEDIATE_NO_ANIM")


class _Paint:
    """Monochrome base with one electric-blue accent.

    truecolor -> 256 colors -> 16 colors -> plain ASCII (no TTY / NO_COLOR / TERM=dumb).
    """

    def __init__(self, stream):
        self.on = _fancy(stream)
        self.uni = self.on and _utf8()
        self.depth = _depth() if self.on else 0

    def __call__(self, code, text):
        return f"\033[{code}m{text}\033[0m" if self.on else str(text)

    def sym(self, fancy, plain):
        return fancy if self.uni else plain

    def rgb(self, rgb, c256, c16, text, extra=""):
        if not self.on:
            return str(text)
        if self.depth == 24:
            code = "38;2;%d;%d;%d" % rgb
        elif self.depth == 256:
            code = f"38;5;{c256}"
        else:
            code = str(c16)
        return self(code + (";" + extra if extra else ""), text)


OUT = _Paint(sys.stdout)
ERR = _Paint(sys.stderr)


def U(fancy, plain):
    return OUT.sym(fancy, plain)


def bold(text, paint=OUT):
    return paint("1", text)


def dim(text, paint=OUT):
    return paint.rgb((120, 124, 132), 244, 90, text)


def white(text, paint=OUT):
    return paint.rgb((245, 247, 250), 255, 97, text, "1")


def accent(text, paint=OUT):
    return paint.rgb((0, 170, 255), 39, 94, text)


def red(text, paint=OUT):
    return paint.rgb((255, 77, 94), 203, 91, text)


def green(text, paint=OUT):
    return paint.rgb((0, 230, 160), 49, 92, text)


def yellow(text, paint=OUT):
    return paint.rgb((255, 200, 60), 221, 93, text)


def cyan(text, paint=OUT):
    return accent(text, paint)


def vlen(text):
    return len(ANSI_RE.sub("", str(text)))


def pad(text, width):
    return str(text) + " " * max(0, width - vlen(text))


def term_width():
    import shutil
    return max(40, min(shutil.get_terminal_size((80, 24)).columns, 100))


BOX = {
    True: dict(tl="╭", tr="╮", bl="╰", br="╯", h="─", v="│", ml="├", mr="┤"),
    False: dict(tl="+", tr="+", bl="+", br="+", h="-", v="|", ml="+", mr="+"),
}


def panel(lines, title="", width=None, edge=None):
    """Rounded box. Grows to fit; if wider than the terminal, drops the right edge."""
    b = BOX[OUT.uni]
    edge = edge or dim
    inner = max([vlen(line) for line in lines] + [vlen(title) + 4, (width or 0) - 4])
    room = term_width()
    closed = inner + 4 <= room
    if not closed:
        # Too wide for the terminal (long URLs are never cut): open right edge,
        # top and bottom rules sized to the terminal.
        inner = max(room - 4, vlen(title) + 4)
    if title:
        top = edge(b["tl"] + b["h"]) + " " + title + " " + edge(b["h"] * max(1, inner - vlen(title) - 1) + b["tr"])
    else:
        top = edge(b["tl"] + b["h"] * (inner + 2) + b["tr"])
    out = [top]
    for line in lines:
        if closed:
            out.append(f"{edge(b['v'])} {pad(line, inner)} {edge(b['v'])}")
        else:
            out.append(f"{edge(b['v'])} {line}")
    out.append(edge(b["bl"] + b["h"] * (inner + 2) + b["br"]))
    return "\n".join(out)


class Spinner:
    """Status line for slow work. Animated only on a real terminal."""

    active = None
    lock = threading.Lock()

    def __init__(self, label, done=None):
        self.label = label
        self.done = done or label
        self.animated = _animated()
        self.frames = "⣾⣽⣻⢿⡿⣟⣯⣷" if OUT.uni else "|/-\\"
        self._stop = threading.Event()
        self._thread = None
        self.started = 0.0

    def __enter__(self):
        Spinner.active = self
        self.started = time.time()
        if self.animated:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print(f"  {U('…', '...')} {self.label}", flush=True)
        return self

    def _spin(self):
        index = 0
        while not self._stop.wait(0.08):
            with Spinner.lock:
                frame = accent(self.frames[index % len(self.frames)])
                secs = time.time() - self.started
                sys.stdout.write(f"\r\033[K  {frame} {white(self.label)} {dim(f'{secs:4.1f}s')}")
                sys.stdout.flush()
            index += 1

    def clear(self):
        if self.animated:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()

    def stop(self):
        if Spinner.active is not self:
            return
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        with Spinner.lock:
            self.clear()
        Spinner.active = None

    def __exit__(self, exc_type, _exc, _tb):
        self.stop()
        if exc_type is None:
            secs = time.time() - self.started
            ok(f"{self.done} {dim(f'{secs:.1f}s')}" if self.animated else self.done)
        return False

    @classmethod
    def stop_active(cls):
        if cls.active is not None:
            cls.active.stop()


def _line(text, stream=None):
    stream = stream or sys.stdout
    with Spinner.lock:
        if Spinner.active is not None:
            Spinner.active.clear()
        print(text, file=stream, flush=True)


def info(msg):
    _line(f"  {accent(U('›', '[i]'))} {msg}")


def ok(msg):
    _line(f"  {green(U('✓', '[ok]'))} {msg}")


def warn(msg):
    _line(f"  {yellow(U('▲', '[!]'))} {yellow(msg)}")


def note(msg):
    """A status message that can show up while a spinner is running."""
    info(msg)


def progress(number):
    if OUT.uni:
        return "".join(accent("━━") if i <= number else dim("──") for i in range(1, TOTAL_STEPS + 1))
    return "[" + "#" * number + "." * (TOTAL_STEPS - number) + "]"


def step(number, title):
    print()
    tag = white(f"{number:02d}") + dim(f"/{TOTAL_STEPS:02d}")
    print(panel([f"{accent(U('▸', '>'))} {white(title.upper() if OUT.on else title)}   {progress(number)}"],
                title=tag, width=64))


LOGO_UNI = [
    "██╗  ██╗ █████╗ ██╗",
    "╚██╗██╔╝██╔══██╗██║",
    " ╚███╔╝ ███████║██║",
    " ██╔██╗ ██╔══██║██║",
    "██╔╝ ██╗██║  ██║██║",
    "╚═╝  ╚═╝╚═╝  ╚═╝╚═╝",
]
LOGO_ASCII = [
    "__  __    _    ___ ",
    "\\ \\/ /   / \\  |_ _|",
    " \\  /   / _ \\  | | ",
    " /  \\  / ___ \\ | | ",
    "/_/\\_\\/_/   \\_\\___|",
]
GRADIENT = [((255, 255, 255), 231, 97), ((205, 232, 255), 195, 97), ((150, 210, 255), 153, 96),
            ((90, 190, 255), 117, 96), ((30, 170, 255), 39, 94), ((0, 140, 230), 33, 94)]


def banner():
    logo = LOGO_UNI if OUT.uni else LOGO_ASCII
    slash = U("╱", "/")
    side = [
        "",
        white("remediate-links"),
        dim(f"NCC {U('·', '|')} FiberMan {U('→', '->')} Chrome {U('→', '->')} sorter"),
        "",
        dim("nothing opens until you confirm"),
        dim(f"q quits {U('·', '|')} ctrl-c cancels"),
    ]
    lines = []
    blank = " " * len(logo[0])
    for i in range(max(len(logo), len(side))):
        rgb, c256, c16 = GRADIENT[min(i, len(GRADIENT) - 1)]
        row = OUT.rgb(rgb, c256, c16, logo[i], "1") if i < len(logo) else blank
        lines.append(("  " + row + "   " + (side[i] if i < len(side) else "")).rstrip())
    rule = dim(slash * 3) + " " + dim(U("─", "-") * 58)
    animate = _motion() and OUT.on
    print()
    for line in lines:
        print(line, flush=True)
        if animate:
            time.sleep(0.05)  # whole reveal is ~0.3s; REMEDIATE_NO_ANIM=1 skips it
    print()
    print("  " + rule)
    print("  Opens one remediation batch in a new Chrome window, then starts the sorter.")
    print("  " + dim("The window you already use for NCC tabs is not changed."))


def die(msg, *hints):
    Spinner.stop_active()
    sys.stdout.flush()
    lines = [part.strip() for part in str(msg).split("Nothing was opened.")]
    main_msg = lines[0] or str(msg).strip()
    nothing = "Nothing was opened." in str(msg)
    print(f"\n  {red(ERR.sym('✗', '[x]'), ERR)} {bold(red(main_msg, ERR), ERR)}", file=sys.stderr)
    for hint in hints:
        print(f"    {dim(hint, ERR)}", file=sys.stderr)
    if nothing:
        print(f"    {dim('Nothing was opened.', ERR)}", file=sys.stderr)
    sys.stderr.flush()
    raise SystemExit(1)


def cancel():
    Spinner.stop_active()
    print()
    if OPENED:
        warn("Stopped. The tabs that were already opened stay open.")
    else:
        warn("Cancelled. Nothing was opened.")
    raise SystemExit(130)


def _read_tty():
    try:
        with open("/dev/tty") as tty:
            line = tty.readline()
    except OSError:
        die(
            "Run this in Terminal so it can ask questions. Nothing was opened.",
            "It reads answers from the terminal, not from the pipe.",
        )
    if not line:
        die("No answer. Nothing was opened.")
    return line.strip()


def ask(prompt, default=None):
    """Ask one question on the terminal. q quits."""
    suffix = f" {dim(f'[{default}]')}" if default not in (None, "") else ""
    print(f"{accent(U('◆', '?'))} {white(prompt)}{suffix} {accent(U('❯', '>'))} ", end="", flush=True)
    answer = _read_tty()
    if answer.casefold() in QUIT_WORDS:
        cancel()
    if not answer and default not in (None, ""):
        return str(default)
    return answer


def _retry(tries, msg):
    left = MAX_TRIES - tries
    if left <= 0:
        die("Too many answers that did not match. Nothing was opened.", "Run it again when you are ready.")
    warn(f"{msg} {dim('(q to quit)')}")


def choose(prompt, options, default=None, key=None, aliases=None, names_first=False, show=True):
    """Numbered menu. options is a list of (value, label, note).

    Accepts the number, the label (case-insensitive, via key), or an alias.
    Enter takes the default (an option number). Re-asks on a bad answer.
    """
    key = key or fold
    aliases = aliases or {}
    if show:
        width = len(str(len(options)))
        label_w = max([vlen(label) for _v, label, _e in options] + [1])
        for index, (_value, label, extra) in enumerate(options, start=1):
            mark = f" {accent('(default)')}" if default == index else ""
            tail = f"  {dim(extra)}" if extra not in (None, "") else ""
            num = accent(f"[{str(index).rjust(width)}]")
            print(f"    {num} {pad(white(label), label_w)}{tail}{mark}")
    tries = 0
    while True:
        answer = ask(prompt, default)
        picked = None
        by_name = [i for i, (_v, label, _e) in enumerate(options) if key(label) == key(answer)]
        if answer and names_first and len(by_name) == 1:
            picked = by_name[0]
        elif answer.isdigit() and 1 <= int(answer) <= len(options):
            picked = int(answer) - 1
        elif answer and len(by_name) == 1:
            picked = by_name[0]
        elif answer and key(answer) in aliases:
            picked = aliases[key(answer)]
        if picked is not None:
            return options[picked][0]
        tries += 1
        if not answer:
            _retry(tries, "Pick one of the options above.")
        else:
            _retry(tries, f'"{answer}" is not one of the options. Type a number from 1 to {len(options)} or a name.')


def ask_text(prompt, default=None, valid=None, problem="That answer did not work."):
    """Free-text answer. Re-asks when blank (and no default) or invalid."""
    tries = 0
    while True:
        answer = ask(prompt, default)
        if answer and (valid is None or valid(answer)):
            return answer
        tries += 1
        _retry(tries, problem if answer else "Type an answer, or q to quit.")


def confirm(prompt, default_yes=False):
    tries = 0
    while True:
        answer = ask(prompt + (" (y/n)"), "Y" if default_yes else "N").casefold()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        tries += 1
        _retry(tries, "Type y or n.")


def summary(rows):
    width = max(len(label) for label, _value in rows)
    lines = [f"{dim(label.upper().ljust(width) if OUT.on else label.ljust(width))}  {value}" for label, value in rows]
    print()
    print(panel(lines, title=white("SUMMARY") if OUT.on else "Summary", edge=accent))
    print()


def launch_screen(count, wid):
    tabs = f"{count} tab{'s' if count != 1 else ''}"
    dot = dim(U(" · ", " | "))
    lines = [
        f"{accent(U('▶', '>'))} {white('LAUNCHING SORTER' if OUT.on else 'Step 5 of 5: launching the sorter')}   {progress(TOTAL_STEPS)}",
        f"{dim('window')} {white(wid)}{dot}{white(tabs)}{dot}{dim('mode')} {white('row')}",
        "",
        "The new window is only these links.",
        "Sorting that window by NA/NB row. Same row keeps the current order.",
        "After the sort, you can switch this same range to triplet, and back.",
        dim(f"Handing over to sort-as-t1-tabs.sh {U('…', '...')}"),
    ]
    tag = white(f"{TOTAL_STEPS:02d}") + dim(f"/{TOTAL_STEPS:02d}")
    print()
    print(panel(lines, title=tag, edge=accent))
    print(flush=True)


def done_screen(code):
    print()
    if code == 0:
        print(f"  {accent(U('╱╱╱', '///'))} {white('done')} {dim(f'{U(chr(183), chr(124))} remediate-links finished')}")
    else:
        print(f"  {yellow(U('▲', '[!]'))} {dim(f'The sorter exited with code {code}. The tabs stay open.')}")


# ---------------------------------------------------------------------------
# Data and Chrome. Logic below is unchanged from the original script, apart
# from status lines (note) and friendlier error text.
# ---------------------------------------------------------------------------


DASHBOARD = (
    "https://supermon.memx.twitter.com/d/ff8a05wtt4wsgc/"
    "front-end-dc-capacity-dashboard-lifecycle-based"
)
DATASOURCE = "cf0f2vv8posn4d"
QUERY = (
    "https://supermon.memx.twitter.com/api/datasources/proxy/uid/"
    + DATASOURCE
    + "/api/v1/query?query="
)
THRESHOLD = 0.005
SORTER = (
    "curl -fsSL https://raw.githubusercontent.com/Cristian8281/"
    "sort-as-t1-tabs/main/sort-as-t1-tabs.sh | bash"
)
NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
RID = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id"
# The dashboard dropdown is the metric label. AS-T1 is as:sis-t1,
# T1-T2 is sis-t1:sis-t2, and T2-T3 is sis-t2:sis-t3.
LINK_TYPES = {
    "as-t1": "as:sis-t1",
    "t1-t2": "sis-t1:sis-t2",
    "t2-t3": "sis-t2:sis-t3",
}
DISC_RE = re.compile(r"^(?:gpu|t\d+)\s*(?:→|->|—|-)\s*(?:t\d+|\?)$", re.I)
HALL_RE = re.compile(r"^dh\d+$", re.I)
SPINE_RE = re.compile(r"-s([1-9]\d?)-", re.I)
LOCATION_HEADERS = {"tier", "location", "data hall", "hall", "dh", "z_location"}



def yes(answer):
    return answer.strip().casefold() in {"y", "yes"}


def fold(text):
    text = (text or "").strip().rstrip(".")
    for ch in ("⁄", "∕", "／"):
        text = text.replace(ch, "/")
    return text.casefold()


def fold_disc(text):
    text = fold(text).replace("→", "-").replace("->", "-").replace("—", "-")
    return re.sub(r"\s+", "", text)

def applescript(source):
    try:
        return subprocess.check_output(["osascript", "-e", source], text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        detail = (exc.output or "Chrome could not be controlled.").strip()
        hints = ["If macOS asked, allow Terminal to control Google Chrome:",
                 "System Settings > Privacy & Security > Automation > Terminal > Google Chrome."]
        die(detail + ("" if OPENED else " Nothing was opened."), *hints)


def chrome_running():
    return subprocess.run(["pgrep", "-x", "Google Chrome"], stdout=subprocess.DEVNULL).returncode == 0


def dashboard_url():
    return (
        DASHBOARD
        + "?orgId=1&from=now-5m&to=now&timezone=browser"
        + f"&var-datasource={DATASOURCE}"
        + "&var-lifecycle=failure.repairing&var-lifecycle=failure.detected"
        + "&var-a_location=$__all"
        + "&var-z_location=$__all"
        + "&var-link_type=$__all"
        + "&var-Filters="
    )


def decrypt_cookie(blob, key):
    if not blob or blob[:3] != b"v10":
        return None
    proc = subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-d", "-K", key.hex(), "-iv", (b" " * 16).hex(), "-nopad"],
        input=blob[3:],
        capture_output=True,
    )
    if proc.returncode != 0 or not proc.stdout:
        return None
    raw = proc.stdout
    pad = raw[-1]
    if not (1 <= pad <= 16 and raw.endswith(bytes([pad]) * pad)):
        return None
    body = raw[:-pad]
    if len(body) <= 32:
        return None
    try:
        return body[32:].decode()
    except UnicodeDecodeError:
        return None


def grafana_cookie():
    try:
        password = subprocess.check_output(
            ["security", "find-generic-password", "-w", "-s", "Chrome Safe Storage", "-a", "Chrome"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip().encode()
    except subprocess.CalledProcessError:
        die("Keychain did not give Chrome Safe Storage. Approve the prompt, then run this again. Nothing was opened.")
    key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1003, 16)
    root = Path.home() / "Library/Application Support/Google/Chrome"
    for db in sorted(root.glob("*/Cookies")):
        try:
            con = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True)
            rows = con.execute(
                "select name, encrypted_value from cookies "
                "where host_key = 'supermon.memx.twitter.com'"
            ).fetchall()
        except sqlite3.Error:
            continue
        finally:
            try:
                con.close()
            except Exception:
                pass
        pairs = []
        for name, blob in rows:
            value = decrypt_cookie(blob, key)
            if value:
                pairs.append(f"{name}={value}")
        if any(pair.startswith("grafana_session=") for pair in pairs):
            return "; ".join(pairs)
    die("No capacity-dashboard login in Chrome. Sign in on that dashboard, then run this again. Nothing was opened.")


def dashboard_state(wid):
    raw = applescript(
        'tell application "Google Chrome"\n'
        f"  set w to window id {int(wid)}\n"
        "  set n to count of tabs of w\n"
        "  repeat with i from 1 to n\n"
        '    if URL of tab i of w contains "ff8a05wtt4wsgc" then\n'
        "      return (loading of tab i of w as text) & linefeed & (title of tab i of w) & linefeed & (URL of tab i of w)\n"
        "    end if\n"
        "  end repeat\n"
        '  return "missing"\n'
        "end tell"
    )
    if raw.strip() == "missing":
        return None
    loading, title, url = (raw.splitlines() + ["", "", ""])[:3]
    return loading.strip(), title.strip(), url.strip()


def wait_dashboard(wid):
    deadline = time.time() + 45
    while time.time() < deadline:
        state = dashboard_state(wid)
        if state is None:
            return False
        loading, title, url = state
        if "accounts.google.com" in url or "/login" in url:
            die("Chrome is not signed in to the capacity dashboard. Nothing was opened.")
        if loading == "false" and "Capacity Dashboard" in title:
            return True
        time.sleep(0.5)
    return False


def find_dashboard_window():
    raw = applescript(
        'tell application "Google Chrome"\n'
        "  repeat with w in windows\n"
        "    repeat with t in tabs of w\n"
        '      if URL of t contains "ff8a05wtt4wsgc" then\n'
        "        return id of w as text\n"
        "      end if\n"
        "    end repeat\n"
        "  end repeat\n"
        '  return ""\n'
        "end tell"
    )
    return raw.strip()


def open_dashboard():
    wid = applescript(
        'tell application "Google Chrome"\n'
        "  set w to make new window\n"
        f'  set URL of active tab of w to "{dashboard_url()}"\n'
        "  return id of w as text\n"
        "end tell"
    ).strip()
    return wid


def reload_dashboard():
    raw = applescript(
        'tell application "Google Chrome"\n'
        "  repeat with w in windows\n"
        "    set n to count of tabs of w\n"
        "    repeat with i from 1 to n\n"
        '      if URL of tab i of w contains "ff8a05wtt4wsgc" then\n'
        "        set active tab index of w to i\n"
        "        reload tab i of w\n"
        "        return id of w as text\n"
        "      end if\n"
        "    end repeat\n"
        "  end repeat\n"
        '  return ""\n'
        "end tell"
    ).strip()
    return raw or open_dashboard()


def warm_dashboard():
    if not chrome_running():
        die("Google Chrome is not running. Nothing was opened.",
            "Open Google Chrome (the profile signed in to the capacity dashboard), then run this again.")
    wid = find_dashboard_window()
    if not wid:
        note("Opening the capacity dashboard.")
        wid = open_dashboard()
    if not wait_dashboard(wid):
        die("The capacity dashboard did not finish loading. Nothing was opened.",
            "Check the dashboard tab in Chrome loads, then run this again.")
    time.sleep(0.6)
    return wid


def prom_query(expr):
    url = QUERY + quote(expr, safe="")
    last_error = "no response"
    for attempt in range(3):
        if attempt:
            note("Refreshing the capacity dashboard login.")
            wid = reload_dashboard()
            wait_dashboard(wid)
            time.sleep(0.8)
        request = urllib.request.Request(
            url,
            headers={
                "cookie": grafana_cookie(),
                "accept": "application/json",
                "origin": "https://supermon.memx.twitter.com",
                "x-grafana-org-id": "1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as resp:
                payload = json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            last_error = exc.read().decode(errors="replace")[:180]
            continue
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
            last_error = str(exc)
            continue
        if payload.get("status") == "success":
            return payload["data"]["result"]
        last_error = str(payload.get("error") or payload.get("messageId") or "rejected")
    die(f"The capacity dashboard rejected the query. {last_error} Nothing was opened.",
        "Open the capacity dashboard in Chrome and make sure you are signed in (and on VPN),",
        "then run this again.")


def pct(value):
    return f"{value * 100:.3f}%"


def series_value(row):
    try:
        return float(row["value"][1])
    except (KeyError, IndexError, TypeError, ValueError):
        return None


def chart_rows(expr, label):
    rows = []
    for item in prom_query(expr):
        name = item.get("metric", {}).get(label)
        value = series_value(item)
        if name and value is not None:
            rows.append((name, value))
    rows.sort(key=lambda item: item[0])
    return rows


def ratio_expr(link_type):
    life = 'lifecycle=~"failure.repairing|failure.detected"'
    base = (
        'environment="production",link_type="%s",a_device_location=~".*",z_device_location=~".*"'
        % link_type
    )
    return (
        "count by (z_device_location) (netcollector_link_assignment{%s,%s}) / "
        "count by (z_device_location) (netcollector_link_assignment{%s})"
        % (base, life, base)
    )


def spine_expr():
    life = 'lifecycle=~"failure.repairing|failure.detected"'
    selector = (
        'environment="production",link_type=~"sis-t2:sis-t3",'
        'a_device_location=~".*",z_device_location=~".*"'
    )

    def wrapped(sel):
        return (
            'label_replace(label_replace(netcollector_link_assignment{%s},'
            '"device_spine","$1","a_device_name",".*-s([1-9][0-9]{0,1})-.*"),'
            '"device_spine","0$1","device_spine","^([1-9])$")' % sel
        )

    return "count by (device_spine) (%s) / count by (device_spine) (%s)" % (
        wrapped(selector + "," + life),
        wrapped(selector),
    )


def print_chart(title, rows):
    red_rows = [(name, value) for name, value in rows if value >= THRESHOLD]
    print(f"  {accent(U('▍', '|'))}{white(title)}")
    if not red_rows:
        print(f"    {green(U('✓', 'ok'))} {dim('none at or over 0.500%')}")
    width = max([len(str(name)) for name, _value in red_rows] + [1])
    top = max([value for _name, value in red_rows] + [THRESHOLD])
    for name, value in red_rows:
        bar = U("█", "#") * max(1, int(round(20 * value / top)))
        print(f"    {red(U('●', '*'))} {white(str(name).ljust(width))}  {red(bar)} {red(pct(value))}")
    print()
    return red_rows


def choose_source():
    step(1, "Where are you remediating from?")
    return choose(
        "Pick a source",
        [
            ("ncc", "NCC", "live capacity dashboard charts"),
            ("sheet", "Report sheet", "FiberMan Google Sheet with an ncc column"),
        ],
        default=1,
        aliases={"n": 0, "ncc": 0, "s": 1, "sheet": 1, "report": 1, "google": 1},
    )


def normalize_place(place):
    token = re.sub(r"[\s.]+", "", (place or "").strip().lower())
    match = re.fullmatch(r"dh(\d+)", token)
    if match:
        return "dh" + match.group(1).zfill(2)
    if token.isdigit():
        return "dh" + token.zfill(2)
    return token


def _disc_key(text):
    key = fold_disc(text)
    if key in {"t3-t2", "t3t2"}:
        key = "t2-t3"
    if key in {"ast1", "as:sis-t1"}:
        key = "as-t1"
    return key


def choose_ncc():
    step(2, "Reading the capacity dashboard")
    info("Threshold is 0.500%. Red rows are at or over it.")
    with Spinner("Waiting for the capacity dashboard in Chrome", "Capacity dashboard is loaded"):
        warm_dashboard()
    with Spinner("Reading the AS-T1, T1-T2 and T2-T3 spine charts", "Read the AS-T1, T1-T2 and T2-T3 spine charts"):
        as_rows = chart_rows(ratio_expr("as:sis-t1"), "z_device_location")
        t1_rows = chart_rows(ratio_expr("sis-t1:sis-t2"), "z_device_location")
        spine_rows = chart_rows(spine_expr(), "device_spine")
    print()
    as_red = print_chart("AS-T1", as_rows)
    t1_red = print_chart("T1-T2", t1_rows)
    spine_red = print_chart("T2-T3 spines", spine_rows)
    halls = []
    seen = set()
    for name, _value in as_red + t1_red:
        if name not in seen:
            seen.add(name)
            halls.append(name)
    if halls:
        info("Data halls and supercores at or over 0.500%: " + white(", ".join(halls)))
    else:
        info("No data hall is at or over 0.500%.")

    step(3, "Discipline and location")
    counts = {"as-t1": len(as_red), "t1-t2": len(t1_red), "t2-t3": len(spine_red)}
    def red_note(key, what):
        n = counts[key]
        return f"{n} {what}{'s' if n != 1 else ''} over threshold" if n else "none over threshold"
    key = choose(
        "Which discipline are you working?",
        [
            ("as-t1", "AS-T1", red_note("as-t1", "location")),
            ("t1-t2", "T1-T2", red_note("t1-t2", "location")),
            ("t2-t3", "T2-T3", red_note("t2-t3", "spine")),
        ],
        key=_disc_key,
    )
    title = {"as-t1": "AS-T1", "t1-t2": "T1-T2", "t2-t3": "T2-T3"}[key]
    selected = {"as-t1": as_red, "t1-t2": t1_red, "t2-t3": spine_red}[key]
    print()
    print_chart(title, selected if key == "t2-t3" else [row for row in (as_rows if key == "as-t1" else t1_rows)])
    # print_chart already printed only the red rows. Re-print is enough.
    link_type = LINK_TYPES[key]
    suggestions = [str(name) for name, _value in selected]
    if key == "t2-t3":
        info("Type a spine number (like 3 or 03), or a data hall / supercore (dh07, sc" + U("…", "...") + ").")
        question = "Which spine, data hall or supercore?"
    else:
        info("Type a data hall (dh07 or just 7) or a supercore (sc" + U("…", "...") + ").")
        question = "Where are you working?"
    if suggestions:
        info("Over threshold now: " + white(", ".join(suggestions)))
    where = ask_text(question, default=suggestions[0] if suggestions else None)
    place = where.strip()
    bare = fold(place).replace(" ", "")
    if key == "t2-t3" and HALL_RE.match(bare) is None and not place.lower().startswith("sc"):
        with Spinner(f"Looking up T2-T3 down links for spine {place}", f"Looked up T2-T3 down links for spine {place}"):
            urls = spine_links(place)
        shown = place
    else:
        shown = normalize_place(place)
        with Spinner(f"Looking up {title} down links at {shown}", f"Looked up {title} down links at {shown}"):
            urls = location_links(link_type, shown)
    return title, shown, link_type, urls


def location_links(link_type, place):
    loc = normalize_place(place)
    expr = (
        'netcollector_link_assignment{environment="production",link_type="%s",'
        'z_device_location="%s",lifecycle=~"failure.repairing|failure.detected"}'
        % (link_type, loc)
    )
    return links_from_series(prom_query(expr))


def spine_links(place):
    wanted = place.strip().lstrip("sS")
    if wanted.isdigit():
        wanted = wanted.zfill(2)
    expr = (
        'netcollector_link_assignment{environment="production",link_type=~"sis-t2:sis-t3",'
        'lifecycle=~"failure.repairing|failure.detected"}'
    )
    kept = []
    for item in prom_query(expr):
        metric = item.get("metric", {})
        name = metric.get("a_device_name", "")
        found = SPINE_RE.search(name)
        spine = found.group(1).zfill(2) if found else ""
        if spine == wanted:
            kept.append(item)
    return links_from_series(kept)


def links_from_series(rows):
    urls = []
    seen = set()
    for item in rows:
        metric = item.get("metric", {})
        device = metric.get("a_device_name") or ""
        iface = metric.get("a_interface") or ""
        if not device or not iface:
            continue
        url = "https://ncc.ts.int-x.ai/network-entity/link/%s/%s" % (
            quote(device, safe=""),
            quote(iface, safe=""),
        )
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    urls.sort()
    return urls


def sheet_id_from(url):
    match = re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", url)
    if not match:
        die("That does not look like a Google Sheet link. Nothing was opened.")
    return match.group(1)


def download_sheet(sheet_id):
    if not chrome_running():
        die("Google Chrome is not running. Nothing was opened.")
    downloads = Path.home() / "Downloads"
    before = {path.name for path in downloads.iterdir() if path.is_file()} if downloads.exists() else set()
    url = f"https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=xlsx"
    wid = applescript(
        'tell application "Google Chrome"\n'
        "  set w to make new window\n"
        f'  set URL of active tab of w to "{url}"\n'
        "  return id of w as text\n"
        "end tell"
    ).strip()
    found = None
    deadline = time.time() + 40
    try:
        while time.time() < deadline:
            current = applescript(
                f'tell application "Google Chrome" to URL of active tab of window id {wid}'
            )
            if "accounts.google.com" in current:
                die("Chrome is not signed in to Google. Nothing was opened.")
            if downloads.exists():
                for path in downloads.iterdir():
                    if not path.is_file() or path.name in before:
                        continue
                    if path.suffix.lower() == ".xlsx" and path.stat().st_size > 1000:
                        time.sleep(0.4)
                        found = path
                        break
            if found:
                break
            time.sleep(0.5)
    finally:
        subprocess.run(
            ["osascript", "-e", f'tell application "Google Chrome" to close window id {wid}'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    if found is None:
        die("The sheet did not download. Stay signed in to Google in Chrome and run this again. Nothing was opened.")
    dest = Path("/tmp/remediate-sheet.xlsx")
    dest.write_bytes(found.read_bytes())
    try:
        found.unlink()
    except OSError:
        pass
    return dest


def col_letters(ref):
    return "".join(ch for ch in ref if ch.isalpha())


def row_number(ref):
    digits = "".join(ch for ch in ref if ch.isdigit())
    return int(digits or 0)


def cell_text(cell, strings):
    kind = cell.attrib.get("t")
    value = cell.find("m:v", NS)
    if kind == "s" and value is not None and value.text:
        return strings[int(value.text)]
    if kind == "inlineStr":
        return "".join(
            node.text or ""
            for node in cell.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t")
        )
    if value is not None and value.text:
        return value.text
    return ""


def workbook_pages(path):
    book = zipfile.ZipFile(path)
    try:
        workbook = ET.fromstring(book.read("xl/workbook.xml"))
        rels = ET.fromstring(book.read("xl/_rels/workbook.xml.rels"))
    finally:
        book.close()
    targets = {rel.attrib["Id"]: rel.attrib["Target"] for rel in rels}
    pages = []
    for sheet in workbook.findall("m:sheets/m:sheet", NS):
        if sheet.attrib.get("state") in {"hidden", "veryHidden"}:
            continue
        name = sheet.attrib["name"]
        target = targets[sheet.attrib[RID]]
        if not target.startswith("xl/"):
            target = "xl/" + target
        pages.append((name, target))
    return pages

def choose_page(pages):
    if len(pages) == 1:
        ok(f'The workbook has one page: "{pages[0][0]}". Using it.')
        return pages[0]
    print()
    print(f"  {accent(U('▍', '|'))}{white('Pages in the workbook')}")
    names = choose("Which page?", [(item, item[0], "") for item in pages])
    return names


def load_sheet_page(path, chosen):
    book = zipfile.ZipFile(path)
    strings = []
    if "xl/sharedStrings.xml" in book.namelist():
        root = ET.fromstring(book.read("xl/sharedStrings.xml"))
        for item in root.findall("m:si", NS):
            strings.append(
                "".join(
                    node.text or ""
                    for node in item.iter("{http://schemas.openxmlformats.org/spreadsheetml/2006/main}t")
                )
            )
    sheet = ET.fromstring(book.read(chosen[1]))
    rel_path = str(Path(chosen[1]).parent / "_rels" / (Path(chosen[1]).name + ".rels"))
    link_for = {}
    if rel_path in book.namelist():
        relationships = ET.fromstring(book.read(rel_path))
        by_id = {rel.attrib["Id"]: rel.attrib.get("Target", "") for rel in relationships}
        hyperlinks = sheet.find("m:hyperlinks", NS)
        if hyperlinks is not None:
            for link in hyperlinks:
                ref = link.attrib.get("ref", "").split(":")[0]
                link_for[(col_letters(ref), row_number(ref))] = by_id.get(link.attrib.get(RID), "")
    cells = {}
    for cell in sheet.findall("m:sheetData/m:row/m:c", NS):
        ref = cell.attrib.get("r", "")
        cells.setdefault(row_number(ref), {})[col_letters(ref)] = cell_text(cell, strings)
    return chosen[0], cells, link_for


def _looks_like_sheet(url):
    return re.search(r"/spreadsheets/d/([a-zA-Z0-9-_]+)", url) is not None


def choose_sheet_urls():
    step(2, "Load the report sheet")
    info("Paste the full link, like https://docs.google.com/spreadsheets/d/" + U("…", "..."))
    sheet_url = ask_text(
        "Paste the Google Sheet link",
        valid=_looks_like_sheet,
        problem="That does not look like a Google Sheet link (it needs /spreadsheets/d/...).",
    )
    with Spinner("Downloading the sheet through Chrome", "Downloaded the sheet"):
        book = download_sheet(sheet_id_from(sheet_url))
    pages = workbook_pages(book)
    if not pages:
        die("That sheet has no pages. Nothing was opened.", "Check it is the right sheet and that a page is visible.")
    page, cells, link_for = load_sheet_page(book, choose_page(pages))
    header_row = None
    ncc_col = None
    for row in sorted(cells):
        for col, value in cells[row].items():
            if fold(value) == "ncc":
                header_row = row
                ncc_col = col
                break
        if ncc_col:
            break
    if not ncc_col:
        die("That page has no column headed ncc. Nothing was opened.",
            "Pick the page whose header row has a column named ncc with NCC hyperlinks.")
    header = cells.get(header_row, {})
    location_col = next((col for col, value in header.items() if fold(value) in LOCATION_HEADERS), None)
    counts = Counter()
    disc_counts = Counter()
    for row, data in cells.items():
        if row <= header_row:
            continue
        for col, value in data.items():
            if HALL_RE.match(fold(value).replace(" ", "")):
                counts[col] += 1
            if DISC_RE.match(value.strip()):
                disc_counts[col] += 1
    if location_col is None and counts:
        location_col = counts.most_common(1)[0][0]
    discipline_col = None
    if disc_counts:
        discipline_col = disc_counts.most_common(1)[0][0]
    if not location_col or not discipline_col:
        die("That page has no location or discipline column. Nothing was opened.",
            "It looks for a location column (tier, location, data hall, hall, dh, z_location or dhNN values)",
            "and a discipline column (values like T1->T2 or GPU->T1).")
    locations = Counter()
    disciplines = Counter()
    records = []
    for row in sorted(cells):
        if row <= header_row:
            continue
        data = cells[row]
        place = (data.get(location_col) or "").strip()
        discipline = (data.get(discipline_col) or "").strip()
        url = link_for.get((ncc_col, row), "")
        if not url:
            continue
        records.append((place, discipline, url))
        if place:
            locations[place] += 1
        if discipline:
            disciplines[discipline] += 1
    ok(f'Page "{page}": column {ncc_col} is NCC, {len(records)} row{"s" if len(records) != 1 else ""} with an NCC link.')
    if not records:
        die("No NCC links matched. Nothing was opened.", "That page has no hyperlinks in the ncc column.")

    step(3, "Location and discipline")

    def place_key(text):
        return fold(text).replace(" ", "")

    def grouped(counter, key_of):
        # Names that compare equal (case, spaces, arrows) are one choice.
        # The label is the most common spelling; the list is sorted by it.
        merged = {}
        for name, count in counter.items():
            if name:
                merged.setdefault(key_of(name), []).append((name, count))
        options = []
        for spellings in merged.values():
            label = sorted(spellings, key=lambda item: (-item[1], item[0]))[0][0]
            total = sum(count for _name, count in spellings)
            options.append((label, label, f"{total} link{'s' if total != 1 else ''}"))
        return sorted(options, key=lambda item: item[0])

    loc_options = grouped(locations, place_key)
    blank_places = sum(1 for place, _d, _u in records if not place)
    if blank_places:
        loc_options.append(("", "(blank)", f"{blank_places} link{'s' if blank_places != 1 else ''} with no location"))
    print(f"  {accent(U('▍', '|'))}{white('Locations')}")
    where = choose(
        "Where are you working?",
        loc_options,
        default=1 if len(loc_options) == 1 else None,
        key=place_key,
        names_first=True,
    )
    wanted_place = fold(where).replace(" ", "")

    here = Counter()
    for place, disc, _url in records:
        if fold(place).replace(" ", "") == wanted_place:
            here[disc] += 1
    disc_options = grouped(here, fold_disc)
    if here.get(""):
        disc_options.append(("", "(blank)", f"{here['']} link{'s' if here[''] != 1 else ''} with no discipline"))
    print()
    print(f"  {accent(U('▍', '|'))}{white('Disciplines at ' + (where or '(blank)'))}")
    discipline = choose(
        "Which discipline are you working?",
        disc_options,
        default=1 if len(disc_options) == 1 else None,
        key=fold_disc,
        names_first=True,
    )
    wanted_disc = fold_disc(discipline)
    urls = []
    seen = set()
    for place, disc, url in records:
        if fold(place).replace(" ", "") != wanted_place:
            continue
        if fold_disc(disc) != wanted_disc:
            continue
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return page, where, discipline, urls


def open_window(urls):
    if not chrome_running():
        die("Google Chrome is not running. Nothing was opened.")
    first, rest = urls[0], urls[1:]
    wid = applescript(
        'tell application "Google Chrome"\n'
        "  set w to make new window\n"
        f'  set URL of active tab of w to "{first}"\n'
        "  return id of w as text\n"
        "end tell"
    ).strip()
    for start in range(0, len(rest), 20):
        chunk = rest[start:start + 20]
        lines = ['tell application "Google Chrome"']
        for url in chunk:
            lines.append(
                f'  make new tab at end of tabs of window id {wid} with properties {{URL:"{url}"}}'
            )
        lines.append("end tell")
        applescript("\n".join(lines))
    check = applescript(
        "tell application \"Google Chrome\"\n"
        f"  set n to count of tabs of window id {wid}\n"
        "  set firstUrl to URL of tab 1 of window id " + wid + "\n"
        "  set lastUrl to URL of last tab of window id " + wid + "\n"
        "  return (n as text) & linefeed & firstUrl & linefeed & lastUrl\n"
        "end tell"
    ).splitlines()

    def same(left, right):
        return unquote(left).rstrip("/") == unquote(right).rstrip("/")

    deadline = time.time() + 8
    while time.time() < deadline:
        if len(check) >= 3 and int(check[0]) == len(urls) and same(check[1], urls[0]) and same(check[2], urls[-1]):
            return wid
        time.sleep(0.4)
        check = applescript(
            "tell application \"Google Chrome\"\n"
            f"  set n to count of tabs of window id {wid}\n"
            "  set firstUrl to URL of tab 1 of window id " + wid + "\n"
            "  set lastUrl to URL of last tab of window id " + wid + "\n"
            "  return (n as text) & linefeed & firstUrl & linefeed & lastUrl\n"
            "end tell"
        ).splitlines()
    die("The new window does not match the link list. Nothing more was opened.")


def set_dashboard_filters(place, link_type):
    token = re.sub(r"[\s.]+", "", (place or "").strip().lower())
    match = re.fullmatch(r"dh(\d+)", token)
    if match:
        token = "dh" + match.group(1).zfill(2)
    loc = token if HALL_RE.match(token) or token.startswith("sc") else "$__all"
    filtered = (
        DASHBOARD
        + "?orgId=1&from=now-5m&to=now&timezone=browser"
        + f"&var-datasource={DATASOURCE}"
        + "&var-lifecycle=failure.repairing&var-lifecycle=failure.detected"
        + "&var-a_location=$__all"
        + "&var-z_location=" + loc
        + "&var-link_type=" + link_type
        + "&var-Filters="
    )
    script = """
tell application "Google Chrome"
  repeat with w in windows
    repeat with t in tabs of w
      if URL of t contains "ff8a05wtt4wsgc" then
        set URL of t to "FILTERED_URL"
        return "updated"
      end if
    end repeat
  end repeat
  return "none"
end tell
""".replace("FILTERED_URL", filtered)
    subprocess.run(["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def confirm_and_open(urls, details=()):
    global OPENED
    count = len(urls)
    if count == 0:
        die("No NCC links matched. Nothing was opened.",
            "Check the location and discipline (or spine) and try again; the charts above show what is over threshold.")
    step(4, "Check and confirm")
    rows = list(details)
    rows.append(("Links", accent(bold(f"{count} link{'s' if count != 1 else ''}"))))
    rows.append(("First", urls[0]))
    if count > 1:
        rows.append(("Last", urls[-1]))
    rows.append(("Opens in", "a new Chrome window (your NCC window is not changed)"))
    summary(rows)
    if not confirm(f"Open {'these ' + str(count) + ' links' if count != 1 else 'this 1 link'} in a new window?"):
        die("Nothing was opened.")
    OPENED = True
    with Spinner(f"Opening {count} tab{'s' if count != 1 else ''} in a new Chrome window",
                 f"Opened {count} tab{'s' if count != 1 else ''} in a new Chrome window"):
        wid = open_window(urls)

    launch_screen(count, wid)
    env = os.environ.copy()
    env["SORT_FIRST_URL"] = urls[0]
    env["SORT_LAST_URL"] = urls[-1]
    env["SORT_WINDOW_ID"] = wid
    env["SORT_MODE"] = "row"
    code = subprocess.call(["bash", "-lc", SORTER], env=env)
    done_screen(code)
    raise SystemExit(code)


def main():
    banner()
    source = choose_source()
    if source == "ncc":
        title, place, link_type, urls = choose_ncc()
        info(f"{title} at {place}, link type {link_type}.")
        with Spinner("Pointing the dashboard tab at this location and link type",
                     "Dashboard tab filtered to this location and link type"):
            set_dashboard_filters(place, link_type)
        details = [("Source", "NCC capacity dashboard"), ("Place", place),
                   ("Discipline", f"{title}  {dim('(' + link_type + ')')}")]
    else:
        page, place, discipline, urls = choose_sheet_urls()
        info(f"{place or '(blank)'} / {discipline or '(blank)'}.")
        details = [("Source", "Report sheet"), ("Page", page), ("Place", place or "(blank)"),
                   ("Discipline", discipline or "(blank)")]
    confirm_and_open(urls, details)


def _run():
    try:
        main()
    except KeyboardInterrupt:
        try:
            cancel()
        except SystemExit as stop:
            raise SystemExit(stop.code)
    except SystemExit:
        raise
    except Exception as exc:  # anything unexpected: say so plainly
        if os.environ.get("REMEDIATE_DEBUG"):
            raise
        die(f"Something went wrong: {exc.__class__.__name__}: {exc}"
            + ("" if OPENED else " Nothing was opened."),
            "Run again with REMEDIATE_DEBUG=1 for the full error.")


if __name__ == "__main__":
    _run()
PY
