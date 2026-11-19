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
# Requires macOS, Google Chrome, and the logins already in that Chrome
# profile. Run it in Terminal. It reads answers from the terminal, not from
# the pipe.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This only runs on macOS, because it opens Google Chrome tabs." >&2
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


def die(msg):
    print(msg, file=__import__("sys").stderr)
    raise SystemExit(1)


def ask(prompt):
    print(prompt, end="", flush=True)
    try:
        with open("/dev/tty") as tty:
            line = tty.readline()
    except OSError:
        die("Run this in Terminal so it can ask questions. Nothing was opened.")
    if not line:
        die("No answer. Nothing was opened.")
    return line.strip()


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
        die((exc.output or "Chrome could not be controlled.").strip())


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
        die("Google Chrome is not running. Nothing was opened.")
    wid = find_dashboard_window()
    if not wid:
        print("Opening the capacity dashboard.")
        wid = open_dashboard()
    if not wait_dashboard(wid):
        die("The capacity dashboard did not finish loading. Nothing was opened.")
    time.sleep(0.6)
    return wid


def prom_query(expr):
    url = QUERY + quote(expr, safe="")
    last_error = "no response"
    for attempt in range(3):
        if attempt:
            print("Refreshing the capacity dashboard login.")
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
    die(f"The capacity dashboard rejected the query. {last_error} Nothing was opened.")


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
    red = [(name, value) for name, value in rows if value >= THRESHOLD]
    print(title)
    if not red:
        print("  none at or over 0.500%")
    for name, value in red:
        print(f"  {name}  {pct(value)}")
    print()
    return red


def choose_source():
    while True:
        answer = ask("Are you remediating on NCC or off the report sheet? [ncc/sheet] ")
        folded = fold(answer)
        if folded in {"n", "ncc", "1"}:
            return "ncc"
        if folded in {"s", "sheet", "report", "google", "2"}:
            return "sheet"
        print("Type ncc or sheet.")


def normalize_place(place):
    token = re.sub(r"[\s.]+", "", (place or "").strip().lower())
    match = re.fullmatch(r"dh(\d+)", token)
    if match:
        return "dh" + match.group(1).zfill(2)
    if token.isdigit():
        return "dh" + token.zfill(2)
    return token


def choose_ncc():
    print("Reading the capacity dashboard. Threshold is 0.500%.")
    print()
    warm_dashboard()
    as_rows = chart_rows(ratio_expr("as:sis-t1"), "z_device_location")
    t1_rows = chart_rows(ratio_expr("sis-t1:sis-t2"), "z_device_location")
    spine_rows = chart_rows(spine_expr(), "device_spine")
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
        print("Data halls and supercores at or over 0.500%:")
        for name in halls:
            print(f"  {name}")
    else:
        print("No data hall is at or over 0.500%.")
    print()
    where = ask("Where are you working? ")
    discipline = ask("Which discipline are you working? [AS-T1/T1-T2/T2-T3] ")
    key = fold_disc(discipline)
    if key in {"t3-t2", "t3t2"}:
        key = "t2-t3"
    if key in {"ast1", "as:sis-t1"}:
        key = "as-t1"
    if key not in LINK_TYPES:
        die("Discipline needs to be AS-T1, T1-T2, or T2-T3. Nothing was opened.")
    title = {"as-t1": "AS-T1", "t1-t2": "T1-T2", "t2-t3": "T2-T3"}[key]
    selected = {"as-t1": as_red, "t1-t2": t1_red, "t2-t3": spine_red}[key]
    print()
    print_chart(title, selected if key == "t2-t3" else [row for row in (as_rows if key == "as-t1" else t1_rows)])
    # print_chart already printed only the red rows. Re-print is enough.
    link_type = LINK_TYPES[key]
    place = where.strip()
    bare = fold(place).replace(" ", "")
    if key == "t2-t3" and HALL_RE.match(bare) is None and not place.lower().startswith("sc"):
        urls = spine_links(place)
        shown = place
    else:
        shown = normalize_place(place)
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
    print()
    print("Pages:")
    for index, (name, _target) in enumerate(pages, start=1):
        print(f"  {index}  {name}")
    print()
    if len(pages) == 1:
        print(f'Using page "{pages[0][0]}".')
        return pages[0]
    while True:
        answer = ask("Which page? ")
        if answer.isdigit():
            number = int(answer)
            if 1 <= number <= len(pages):
                return pages[number - 1]
        else:
            matches = [item for item in pages if item[0] == answer or fold(item[0]) == fold(answer)]
            if len(matches) == 1:
                return matches[0]
        print(f"Type a number from 1 to {len(pages)}.")


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


def choose_sheet_urls():
    sheet_url = ask("Paste the Google Sheet link: ")
    book = download_sheet(sheet_id_from(sheet_url))
    pages = workbook_pages(book)
    if not pages:
        die("That sheet has no pages. Nothing was opened.")
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
        die("That page has no column headed ncc. Nothing was opened.")
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
        die("That page has no location or discipline column. Nothing was opened.")
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
    print()
    print(f'Page "{page}". Column {ncc_col} is NCC.')
    print("Locations:")
    for name, count in sorted(locations.items(), key=lambda item: item[0]):
        print(f"  {name}  {count}")
    print("Disciplines:")
    for name, count in sorted(disciplines.items(), key=lambda item: item[0]):
        print(f"  {name}  {count}")
    print()
    where = ask("Where are you working? ")
    discipline = ask("Which discipline are you working? ")
    wanted_place = fold(where).replace(" ", "")
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


def confirm_and_open(urls):
    count = len(urls)
    if count == 0:
        die("No NCC links matched. Nothing was opened.")
    print(f"{count} link{'s' if count != 1 else ''}.")
    print(urls[0])
    if count > 1:
        print(urls[-1])
    if not yes(ask(f"Open these {count} links in a new window? [y/N] ")):
        die("Nothing was opened.")
    wid = open_window(urls)
    print()
    print("The new window is only these links.")
    print("Sorting that window by NA/NB row. Same row keeps the current order.")
    print("After the sort, you can switch this same range to triplet, and back.")
    print()
    env = os.environ.copy()
    env["SORT_FIRST_URL"] = urls[0]
    env["SORT_LAST_URL"] = urls[-1]
    env["SORT_WINDOW_ID"] = wid
    env["SORT_MODE"] = "row"
    raise SystemExit(subprocess.call(["bash", "-lc", SORTER], env=env))


def main():
    print("This opens one remediation batch in a new Chrome window, then starts the sorter.")
    print("The window you already use for NCC tabs is not changed.")
    print()
    source = choose_source()
    if source == "ncc":
        title, place, link_type, urls = choose_ncc()
        print(f"{title} at {place}, link type {link_type}.")
        set_dashboard_filters(place, link_type)
    else:
        _page, place, discipline, urls = choose_sheet_urls()
        print(f"{place} / {discipline}.")
    confirm_and_open(urls)


if __name__ == "__main__":
    main()
PY
