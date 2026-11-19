#!/bin/bash
# Sort a marked range of Chrome NCC link tabs.
#
# The script asks two things before it moves anything:
#   1. The divider name that starts the range. The next divider ends it.
#   2. triplet (RAM, RCK, ZUC) or row (na05, na12, nb05).
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Cristian8281/sort-as-t1-tabs/main/sort-as-t1-tabs.sh | bash
#   curl -fsSL https://raw.githubusercontent.com/Cristian8281/sort-as-t1-tabs/main/sort-as-t1-tabs.sh | bash -s -- --dry-run
#
# Requires macOS, Google Chrome, and an NCC login in that Chrome profile.
# The first run asks Keychain for the Chrome Safe Storage password.
set -euo pipefail

if [ "$(uname -s)" != "Darwin" ]; then
  echo "This only runs on macOS, because it reorders Google Chrome tabs." >&2
  exit 1
fi

exec python3 - "$@" << 'PY'
import hashlib
import json
import re
import sqlite3
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

NCC = "https://ncc.ts.int-x.ai/graphql"
DRY = "--dry-run" in sys.argv[1:]
ROW_RE = re.compile(r"^([a-z]+)(\d+)$")


def die(msg):
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def ask(prompt):
    print(prompt, end="", flush=True)
    try:
        with open("/dev/tty") as tty:
            line = tty.readline()
    except OSError:
        die("Run this in Terminal so it can ask which tabs to sort. Nothing was moved.")
    if not line:
        die("No answer. Nothing was moved.")
    return line.strip()


def checklist():
    print(
        """Before this sorts anything, have these ready:

1. A range of tabs in Chrome.
   Put one tab divider immediately before the first link,
   and another tab divider immediately after the last link.
   The tabs between those two dividers are the ones that get sorted.

2. Which order you want.
   triplet    RAM, RCK, ZUC. The three letters on the memy switch.
   row        na05, na12, nb05. The NA/NB row on the device in the tab.

Chrome needs to be open and signed in to NCC.
The first run asks for the Chrome keychain password.
Nothing moves until you confirm.
"""
    )


def choose_mode():
    start = ask("Starting divider name: ")
    if not start:
        die("Need the divider name that starts the range. Nothing was moved.")
    raw = ask("Sort by [triplet/row]: ").lower()
    if raw in ("t", "triplet", "1"):
        return start, "triplet"
    if raw in ("r", "row", "2", "na", "nb", "na/nb"):
        return start, "row"
    die("Type triplet or row. Nothing was moved.")


def chrome_tabs():
    if subprocess.run(["pgrep", "-x", "Google Chrome"], stdout=subprocess.DEVNULL).returncode != 0:
        die("Google Chrome is not running. Nothing was moved.")
    script = r'''
tell application "Google Chrome"
  if (count of windows) is 0 then error "Chrome has no windows"
  set sep to ASCII character 31
  set output to ""
  repeat with wi from 1 to (count of windows)
    set w to window wi
    set wid to id of w as text
    set n to count of tabs of w
    repeat with t from 1 to n
      set output to output & wid & sep & (id of tab t of w as text) & sep & (URL of tab t of w) & linefeed
    end repeat
  end repeat
  return output
end tell
'''
    try:
        raw = subprocess.check_output(["osascript", "-e", script], text=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as exc:
        die(exc.stderr.decode(errors="replace").strip() or "Could not read Chrome tabs. Nothing was moved.")
    windows = {}
    for line in raw.splitlines():
        if not line.strip():
            continue
        wid, tid, url = line.split("\x1f", 2)
        windows.setdefault(wid, []).append({"tid": tid, "url": url})
    return windows


def divider_name(url):
    if "divider.html" not in url:
        return None
    name = (parse_qs(urlparse(url).query).get("name") or [""])[0]
    return name or None


def link_parts(url):
    path = unquote(urlparse(url).path).strip("/").split("/")
    if len(path) < 4 or path[0] != "network-entity" or path[1] != "link":
        return None
    return path[2], "/".join(path[3:])


def divider_names(windows):
    names = []
    for tabs in windows.values():
        for tab in tabs:
            name = divider_name(tab["url"])
            if name and name not in names:
                names.append(name)
    return names


def find_block(windows, start_name):
    want = start_name.lower()
    found = []
    for wid, tabs in windows.items():
        for i, tab in enumerate(tabs):
            if (divider_name(tab["url"]) or "").lower() != want:
                continue
            end = next((j for j in range(i + 1, len(tabs)) if divider_name(tabs[j]["url"])), None)
            if end is None:
                die(
                    f'"{start_name}" has no divider after it. '
                    "Put a second divider immediately after the last tab you want sorted. Nothing was moved."
                )
            block = tabs[i + 1:end]
            found.append((wid, tab, tabs[end], block))
    if not found:
        names = divider_names(windows)
        extra = f" Dividers open now: {', '.join(names)}." if names else " No tab dividers are open."
        die(f'No divider named "{start_name}".{extra} Nothing was moved.')
    if len(found) > 1:
        die(f'More than one divider is named "{start_name}". Rename one so the range is unique. Nothing was moved.')
    wid, start, end, block = found[0]
    if not block:
        die(f'Nothing is between "{divider_name(start["url"])}" and "{divider_name(end["url"])}". Nothing was moved.')
    stray = [t for t in block if link_parts(t["url"]) is None]
    if stray:
        die(
            "A tab inside that range is not an NCC link. "
            "Move it outside the two dividers and run this again. Nothing was moved."
        )
    return wid, start, end, block


def chrome_key():
    try:
        password = subprocess.check_output(
            ["security", "find-generic-password", "-w", "-s", "Chrome Safe Storage", "-a", "Chrome"],
            text=True, stderr=subprocess.PIPE,
        ).strip().encode()
    except subprocess.CalledProcessError:
        die("Keychain did not give Chrome Safe Storage. Approve the prompt, then run this again. Nothing was moved.")
    return hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1003, 16)


def decrypt_cookie(blob, key):
    if not blob or blob[:3] != b"v10":
        return None
    proc = subprocess.run(
        ["openssl", "enc", "-aes-128-cbc", "-d", "-K", key.hex(), "-iv", (b" " * 16).hex(), "-nopad"],
        input=blob[3:], capture_output=True,
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


def cookie_header(key):
    root = Path.home() / "Library/Application Support/Google/Chrome"
    for db in sorted(root.glob("*/Cookies")):
        uri = db.as_uri() + "?mode=ro"
        try:
            con = sqlite3.connect(uri, uri=True)
            rows = con.execute(
                "select host_key, name, encrypted_value from cookies "
                "where host_key in ('.int-x.ai', 'ncc.ts.int-x.ai')"
            ).fetchall()
        except sqlite3.Error:
            continue
        finally:
            try:
                con.close()
            except Exception:
                pass
        pairs = []
        for _host, name, blob in rows:
            value = decrypt_cookie(blob, key)
            if value:
                pairs.append(f"{name}={value}")
        if any(pair.startswith("session=") for pair in pairs):
            return "; ".join(pairs)
    die("No NCC login cookie in Chrome. Open https://ncc.ts.int-x.ai and sign in, then run this again. Nothing was moved.")


def triplet(host):
    if not host:
        return None
    fields = host.split("-")
    if len(fields) >= 2 and len(fields[1]) == 3 and fields[1].isalpha():
        return fields[1].upper()
    return None


def choose_triplet(device, remote):
    remote_tri = triplet(remote)
    local_tri = triplet(device)
    remote_l = (remote or "").lower()
    if remote and "-as" in remote_l and remote_tri:
        return remote_tri
    if "-as" in device.lower() and local_tri:
        return local_tri
    return remote_tri or local_tri


def row_key(rack):
    text = (rack or "").lower()
    match = ROW_RE.match(text)
    if match:
        return (0, match.group(1), int(match.group(2)))
    return (1, text, 0)


def lookup(cookie, device, iface):
    query = """query ($device: String!, $interface: String!) {
      networkDevice(device: $device) {
        location { rack actual_rack }
        ports(name: $interface) { link { remote_uuid } }
      }
    }"""
    body = json.dumps({"query": query, "variables": {"device": device, "interface": iface}}).encode()
    req = urllib.request.Request(
        NCC, data=body,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "cookie": cookie,
            "origin": "https://ncc.ts.int-x.ai",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=40) as resp:
            data = json.loads(resp.read().decode())
    except Exception as exc:
        detail = ""
        if hasattr(exc, "read"):
            detail = exc.read().decode(errors="replace")[:200]
        return {"error": f"{device} {iface}: {exc.__class__.__name__} {detail}".strip()}
    if data.get("errors") and not (data.get("data") or {}).get("networkDevice"):
        return {"error": f"{device} {iface}: {json.dumps(data['errors'])[:200]}"}
    device_info = (data.get("data") or {}).get("networkDevice") or {}
    location = device_info.get("location") or {}
    rack = (location.get("rack") or location.get("actual_rack") or "").lower() or None
    ports = device_info.get("ports") or []
    remote = None
    for port in ports:
        link = (port or {}).get("link") or {}
        if link.get("remote_uuid"):
            remote = link["remote_uuid"]
            break
    return {"triplet": choose_triplet(device, remote), "rack": rack, "remote": remote}


def as_string(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def reorder(window_id, old_ids, urls, boundary_id):
    script = r'''
tell application "Google Chrome"
  set w to window id WID
  set createdIds to {}
  try
    set n to count of tabs of w
    set startIdx to 0
    repeat with i from 1 to n
      if (id of tab i of w as text) is FIRST then
        set startIdx to i
        exit repeat
      end if
    end repeat
    if startIdx is 0 then error "the tab range is gone"
    set lastIdx to startIdx + COUNT - 1
    if lastIdx > n then error "the tab range moved"
CHECKS
    set insertAt to lastIdx + 1
    if insertAt > (count of tabs of w) then
INSERT_END
    else
      if BOUNDARY is not "" then
        if (id of tab insertAt of w as text) is not BOUNDARY then error "the divider after the range moved"
      end if
INSERT_BEFORE
    end if
    set newStart to startIdx + COUNT
VERIFY
    repeat COUNT times
      close tab startIdx of w
    end repeat
    return "reordered"
  on error errMsg
    set n2 to count of tabs of w
    repeat with i from n2 to 1 by -1
      set tid to id of tab i of w as text
      if createdIds contains tid then close tab i of w
    end repeat
    error errMsg
  end try
end tell
'''
    checks = []
    for offset, tid in enumerate(old_ids):
        checks.append(
            f'    if (id of tab (startIdx + {offset}) of w as text) is not "{tid}" then error "tabs changed before reorder"'
        )
    insert_end = []
    insert_before = []
    verify = []
    for index, url in enumerate(urls):
        insert_end.append(f"      set newTab to make new tab at end of tabs of w with properties {{URL:{as_string(url)}}}")
        insert_end.append("      set end of createdIds to (id of newTab as text)")
        insert_before.append(f"      set newTab to make new tab at before tab insertAt of w with properties {{URL:{as_string(url)}}}")
        insert_before.append("      set end of createdIds to (id of newTab as text)")
        insert_before.append("      set insertAt to insertAt + 1")
        verify.append(
            f'    if URL of tab (newStart + {index}) of w is not {as_string(url)} then error "new tab URL did not land in order"'
        )
    script = (
        script.replace("WID", str(int(window_id)))
        .replace("FIRST", as_string(old_ids[0]))
        .replace("COUNT", str(len(old_ids)))
        .replace("BOUNDARY", as_string(boundary_id or ""))
        .replace("CHECKS", "\n".join(checks))
        .replace("INSERT_END", "\n".join(insert_end))
        .replace("INSERT_BEFORE", "\n".join(insert_before))
        .replace("VERIFY", "\n".join(verify))
    )
    try:
        subprocess.check_output(["osascript", "-e", script], text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        die(exc.output.strip() or "Chrome reorder failed. Existing tabs were left in place if the new ones could be closed.")


def summarize(ordered, field):
    groups = []
    for item in ordered:
        label = item[field]
        if not groups or groups[-1][0] != label:
            groups.append([label, 1])
        else:
            groups[-1][1] += 1
    return ", ".join(f"{name} x{count}" for name, count in groups)


def main():
    checklist()
    start_name, mode = choose_mode()
    windows = chrome_tabs()
    wid, start, end, block = find_block(windows, start_name)
    end_name = divider_name(end["url"])
    print(f'Reading {len(block)} tabs between "{divider_name(start["url"])}" and "{end_name}"...', flush=True)
    key = chrome_key()
    cookie = cookie_header(key)
    jobs = []
    for tab in block:
        device, iface = link_parts(tab["url"])
        jobs.append((tab, device, iface))

    def run(job):
        tab, device, iface = job
        result = lookup(cookie, device, iface)
        result["tab"] = tab
        return result

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, jobs))
    missing = []
    for item in results:
        if item.get("error"):
            missing.append(item["error"])
        elif mode == "triplet" and not item.get("triplet"):
            device, iface = link_parts(item["tab"]["url"])
            missing.append(f"{device} {iface}: no rack triplet")
        elif mode == "row" and not item.get("rack"):
            device, iface = link_parts(item["tab"]["url"])
            missing.append(f"{device} {iface}: no NA/NB row")
    if missing:
        print("\n".join(missing[:12]), file=sys.stderr)
        die(f"Could not read a sort key for {len(missing)} tab(s). Nothing was moved.")
    if mode == "triplet":
        ordered = sorted(results, key=lambda item: item["triplet"])
        field = "triplet"
    else:
        ordered = sorted(results, key=lambda item: row_key(item["rack"]))
        field = "rack"
    print(summarize(ordered, field))
    already = [item["tab"]["tid"] for item in results] == [item["tab"]["tid"] for item in ordered]
    if already:
        print("Already in that order. Nothing was moved.")
        return
    if DRY:
        print("Dry run. Nothing was moved.")
        return
    answer = ask("Reorder them? The tabs will reload. [y/N] ")
    if answer.lower() not in ("y", "yes"):
        print("Nothing was moved.")
        return
    reorder(
        wid,
        [item["tab"]["tid"] for item in results],
        [item["tab"]["url"] for item in ordered],
        end["tid"],
    )
    label = "triplet" if mode == "triplet" else "row"
    print(f"Done. Walk the tabs left to right by {label}.")


if __name__ == "__main__":
    main()
PY
