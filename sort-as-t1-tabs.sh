#!/bin/bash
# Sort a range of Chrome NCC link tabs.
#
# After you paste the command, it asks for the first and last tab in the
# range, checks that it can read Chrome and NCC, asks you to confirm every
# tab is open, then asks whether to sort by NA/NB row or by rack triplet.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Cristian8281/sort-as-t1-tabs/main/sort-as-t1-tabs.sh | bash
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
from urllib.parse import unquote, urlparse

NCC = "https://ncc.ts.int-x.ai/graphql"
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
        die("Run this in Terminal so it can ask questions. Nothing was moved.")
    if not line:
        die("No answer. Nothing was moved.")
    return line.strip()


def link_parts(url):
    path = unquote(urlparse(url.strip()).path).strip("/").split("/")
    if len(path) < 4 or path[0] != "network-entity" or path[1] != "link":
        return None
    return path[2], "/".join(path[3:])


def link_key(url):
    parts = link_parts(url)
    if not parts:
        return None
    device, iface = parts
    return device.lower(), iface


def ask_range():
    print("Paste the first and last tab in the range you want sorted.")
    print("The sort includes those two tabs and every tab between them.")
    print()
    first = ask("URL of the first tab: ")
    last = ask("URL of the last tab: ")
    if link_key(first) is None or link_key(last) is None:
        die("Both URLs need to be NCC link tabs, like https://ncc.ts.int-x.ai/network-entity/link/... Nothing was moved.")
    return first, last


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
      set output to output & wid & sep & (id of tab t of w as text) & sep & (title of tab t of w) & sep & (URL of tab t of w) & linefeed
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
        wid, tid, title, url = line.split("\x1f", 3)
        windows.setdefault(wid, []).append({"tid": tid, "title": title, "url": url})
    if not windows:
        die("Chrome has no tabs. Nothing was moved.")
    return windows


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


def check_access(start_url):
    print("Checking Chrome and NCC access...")
    windows = chrome_tabs()
    tab_count = sum(len(tabs) for tabs in windows.values())
    print(f"  Chrome is open. Can read {tab_count} tabs in {len(windows)} window(s), including titles and URLs.")
    key = chrome_key()
    print("  Keychain access works.")
    cookie = cookie_header(key)
    print("  NCC login found.")
    device, iface = link_parts(start_url)
    probe = lookup(cookie, device, iface)
    if probe.get("error"):
        die(f"NCC did not return that link. {probe['error']} Nothing was moved.")
    print("  Can read link data from NCC.")
    print()
    return windows, cookie


def find_range(windows, first_url, last_url):
    start_key = link_key(first_url)
    end_key = link_key(last_url)
    found = []
    for wid, tabs in windows.items():
        starts = [i for i, tab in enumerate(tabs) if link_key(tab["url"]) == start_key]
        ends = [i for i, tab in enumerate(tabs) if link_key(tab["url"]) == end_key]
        for start in starts:
            later = [end for end in ends if end >= start]
            if later:
                found.append((wid, start, later[0], tabs))
    if not found:
        die("Those two tabs are not open together in one Chrome window, with the first tab left of the last. Nothing was moved.")
    if len(found) > 1:
        die("That first or last tab is open more than once. Close the extra copy so the range is unique. Nothing was moved.")
    wid, start, end, tabs = found[0]
    block = tabs[start:end + 1]
    stray = [tab for tab in block if link_key(tab["url"]) is None]
    if stray:
        die("A tab inside that range is not an NCC link. Move it outside the range and run this again. Nothing was moved.")
    boundary = tabs[end + 1]["tid"] if end + 1 < len(tabs) else ""
    return wid, block, boundary


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
        if (id of tab insertAt of w as text) is not BOUNDARY then error "the tab after the range moved"
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


def ask_sort_mode():
    print("How should they be sorted?")
    print("  row       NA/NB row, alphabetically and numerically (na05, na12, nb05)")
    print("  triplet   rack triplet, alphabetically (RAM, RCK, ZUC)")
    raw = ask("Sort by [row/triplet]: ").lower()
    if raw in ("r", "row", "1", "na", "nb", "na/nb"):
        return "row"
    if raw in ("t", "triplet", "2"):
        return "triplet"
    die("Type row or triplet. Nothing was moved.")


def main():
    first_url, last_url = ask_range()
    print()
    windows, cookie = check_access(first_url)
    wid, block, boundary = find_range(windows, first_url, last_url)
    print(f"Found {len(block)} tabs in that range.")
    print()
    ready = ask("Do you have all the tabs you need open before I sort them? [y/N] ")
    if ready.lower() not in ("y", "yes"):
        print("Open the rest, then run the command again. Nothing was moved.")
        return
    print()
    mode = ask_sort_mode()
    print()
    print(f"Reading {len(block)} tabs...", flush=True)
    jobs = [(tab, *link_parts(tab["url"])) for tab in block]

    def run(job):
        tab, device, iface = job
        result = lookup(cookie, device, iface)
        result["tab"] = tab
        return result

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(run, jobs))
    missing = []
    for item in results:
        device, iface = link_parts(item["tab"]["url"])
        if item.get("error"):
            missing.append(item["error"])
        elif mode == "triplet" and not item.get("triplet"):
            missing.append(f"{device} {iface}: no rack triplet")
        elif mode == "row" and not item.get("rack"):
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
    reorder(
        wid,
        [item["tab"]["tid"] for item in results],
        [item["tab"]["url"] for item in ordered],
        boundary,
    )
    label = "row" if mode == "row" else "triplet"
    print(f"Done. Walk the tabs left to right by {label}.")


if __name__ == "__main__":
    main()
PY
