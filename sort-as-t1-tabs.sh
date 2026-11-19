#!/bin/bash
# Sort a range of Chrome NCC link tabs.
#
# After you paste the command, it asks for the first and last tab in the
# range, checks that it can read Chrome and NCC, asks you to confirm every
# tab is open, then asks whether to sort by NA/NB row or by rack triplet.
# It then asks if you want to switch that same range between row and triplet.
# Duplicate copies of an end tab are included. The span is the leftmost
# first tab through the rightmost last tab. One copy of each link is kept.
# The script checks the tab strip after the move and does not say it is
# done until that strip matches the sort.
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
    print("Duplicate copies are included, from the leftmost first tab to the rightmost last tab.")
    print("One copy of each link is kept.")
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
        if not starts or not ends or ends[-1] < starts[0]:
            continue
        found.append((wid, starts[0], ends[-1], tabs))
    if not found:
        die("Those two tabs are not open together in one Chrome window, with the first tab left of the last. Nothing was moved.")
    if len(found) > 1:
        die("That range is open in more than one Chrome window. Close the extra one and run this again. Nothing was moved.")
    wid, start, end, tabs = found[0]
    block = tabs[start:end + 1]
    stray = [tab for tab in block if link_key(tab["url"]) is None]
    if stray:
        die("A tab inside that range is not an NCC link. Move it outside the range and run this again. Nothing was moved.")
    boundary = tabs[end + 1]["tid"] if end + 1 < len(tabs) else ""
    return wid, block, boundary


def as_string(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def applescript(source):
    try:
        return subprocess.check_output(["osascript", "-e", source], text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        die(exc.output.strip() or "Chrome reorder failed.")


def reorder(window_id, old_ids, urls, boundary_id):
    url_list = ", ".join(as_string(url) for url in urls)
    old_list = ", ".join(as_string(tid) for tid in reversed(old_ids))
    boundary = as_string(boundary_id or "")
    create = f'''
tell application "Google Chrome"
  set w to window id {int(window_id)}
  set createdIds to {{}}
  set urlList to {{{url_list}}}
  set boundary to {boundary}
  try
    set urlCount to count of urlList
    repeat with k from 1 to urlCount
      set targetUrl to item k of urlList as text
      if boundary is "" then
        set newTab to make new tab at end of tabs of w with properties {{URL:targetUrl}}
      else
        set insertAt to 0
        set n to count of tabs of w
        repeat with i from 1 to n
          if (id of tab i of w as text) is boundary then
            set insertAt to i
            exit repeat
          end if
        end repeat
        if insertAt is 0 then error "the tab after the range moved"
        set newTab to make new tab at before tab insertAt of w with properties {{URL:targetUrl}}
      end if
      set end of createdIds to (id of newTab as text)
      delay 0.12
    end repeat
  on error errMsg
    set n2 to count of tabs of w
    repeat with i from n2 to 1 by -1
      set tid to id of tab i of w as text
      if createdIds contains tid then close tab i of w
    end repeat
    error errMsg
  end try
  set out to ""
  set nCreated to count of createdIds
  repeat with k from 1 to nCreated
    set out to out & (item k of createdIds as text) & linefeed
  end repeat
  return out
end tell
'''
    created = [line.strip() for line in applescript(create).splitlines() if line.strip()]
    if len(created) != len(urls):
        die("Chrome did not open every sorted tab. Nothing else was changed.")
    close = f'''
tell application "Google Chrome"
  set w to window id {int(window_id)}
  set pending to {{{old_list}}}
  set passes to 0
  repeat while (count of pending) > 0 and passes < 8
    set passes to passes + 1
    set nClose to count of tabs of w
    set nextPending to {{}}
    repeat with k from 1 to (count of pending)
      set wanted to item k of pending as text
      set foundIdx to 0
      repeat with i from nClose to 1 by -1
        if (id of tab i of w as text) is wanted then
          set foundIdx to i
          exit repeat
        end if
      end repeat
      if foundIdx is 0 then
        -- already closed
      else
        close tab foundIdx of w
        set end of nextPending to wanted
        set nClose to count of tabs of w
      end if
    end repeat
    set pending to nextPending
    if (count of pending) > 0 then delay 0.25
  end repeat
  if (count of pending) > 0 then error "an original tab stayed open"
  return "closed"
end tell
'''
    applescript(close)
    windows = chrome_tabs()
    tabs = windows.get(str(window_id))
    if tabs is None:
        die("Lost the Chrome window after reorder.")
    by_id = {tab["tid"]: tab for tab in tabs}
    left = [tid for tid in old_ids if tid in by_id]
    if left:
        die(f"{len(left)} original tab(s) stayed open. The sorted tabs are also open.")
    positions = []
    for tid, url in zip(created, urls):
        tab = by_id.get(tid)
        if tab is None or link_key(tab["url"]) != link_key(url):
            die("A sorted tab did not stay open at its URL.")
        positions.append(next(i for i, item in enumerate(tabs) if item["tid"] == tid))
    if positions != list(range(positions[0], positions[0] + len(positions))):
        die("The sorted tabs are not in one block.")
    if boundary_id:
        boundary_at = next((i for i, item in enumerate(tabs) if item["tid"] == boundary_id), None)
        if boundary_at != positions[-1] + 1:
            die("The tab after the range is not where it started.")
    return created


def summarize(ordered, field):
    groups = []
    for item in ordered:
        label = item[field]
        if not groups or groups[-1][0] != label:
            groups.append([label, 1])
        else:
            groups[-1][1] += 1
    return ", ".join(f"{name} x{count}" for name, count in groups)


def parse_mode(raw):
    raw = raw.lower()
    if raw in ("r", "row", "1", "na", "nb", "na/nb"):
        return "row"
    if raw in ("t", "triplet", "2"):
        return "triplet"
    return None


def ask_sort_mode():
    print("How should they be sorted?")
    print("  row       NA/NB row, alphabetically and numerically (na05, na12, nb05)")
    print("  triplet   rack triplet, alphabetically (RAM, RCK, ZUC)")
    mode = parse_mode(ask("Sort by [row/triplet]: "))
    if mode is None:
        die("Type row or triplet. Nothing was moved.")
    return mode


def ask_switch():
    print()
    print("Switch this same range back and forth, or leave it.")
    print("  row       NA/NB row, alphabetically and numerically (na05, na12, nb05)")
    print("  triplet   rack triplet, alphabetically (RAM, RCK, ZUC)")
    print("  done      leave the tabs as they are")
    while True:
        raw = ask("Switch to [row/triplet/done]: ").lower()
        if raw in ("", "n", "no", "d", "done", "q", "quit"):
            return None
        mode = parse_mode(raw)
        if mode:
            return mode
        print("Type row, triplet, or done.")


def range_by_links(windows, window_id, boundary_id, link_keys):
    tabs = windows.get(str(window_id))
    if not tabs:
        die("Lost the Chrome window. Nothing more was moved.")
    if boundary_id:
        end = next((i for i, tab in enumerate(tabs) if tab["tid"] == boundary_id), None)
        if end is None:
            die("The tab after the range moved. Nothing more was moved.")
    else:
        end = len(tabs)
    start = end - len(link_keys)
    if start < 0:
        die("The range changed. Nothing more was moved.")
    block = tabs[start:end]
    if {link_key(tab["url"]) for tab in block} != link_keys:
        die("The range changed. Nothing more was moved.")
    return block, boundary_id or ""


def load_results(block, cookie, cache):
    jobs = []
    for tab in block:
        key = link_key(tab["url"])
        if key not in cache:
            device, iface = link_parts(tab["url"])
            jobs.append((key, device, iface))
    if jobs:
        def run(job):
            key, device, iface = job
            result = lookup(cookie, device, iface)
            result["key"] = key
            return result
        with ThreadPoolExecutor(max_workers=8) as pool:
            for result in pool.map(run, jobs):
                cache[result["key"]] = result
    loaded = []
    for tab in block:
        saved = cache[link_key(tab["url"])]
        loaded.append({
            "triplet": saved.get("triplet"),
            "rack": saved.get("rack"),
            "remote": saved.get("remote"),
            "error": saved.get("error"),
            "tab": tab,
        })
    return loaded


def apply_sort(mode, results, wid, boundary):
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
    kept = []
    seen = set()
    for item in ordered:
        key = link_key(item["tab"]["url"])
        if key in seen:
            continue
        seen.add(key)
        kept.append(item)
    dropped = len(ordered) - len(kept)
    if dropped:
        print(f"Keeping one copy of each link. {dropped} duplicate tab(s) will be closed.")
    print(summarize(kept, field))
    current = []
    seen = set()
    for item in results:
        key = link_key(item["tab"]["url"])
        if key in seen:
            continue
        seen.add(key)
        current.append(item["tab"]["tid"])
    label = "row" if mode == "row" else "triplet"
    keys = {link_key(item["tab"]["url"]) for item in kept}
    if dropped == 0 and current == [item["tab"]["tid"] for item in kept]:
        print(f"Already in {label} order. Nothing was moved.")
        return keys
    print(f"Reordering {len(kept)} tabs. They will reload.", flush=True)
    reorder(
        wid,
        [item["tab"]["tid"] for item in results],
        [item["tab"]["url"] for item in kept],
        boundary,
    )
    print(f"Done. Walk the tabs left to right by {label}.")
    return keys


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
    cache = {}
    link_keys = None
    while True:
        print()
        if link_keys is not None:
            windows = chrome_tabs()
            block, boundary = range_by_links(windows, wid, boundary, link_keys)
        print(f"Reading {len(block)} tabs...", flush=True)
        results = load_results(block, cookie, cache)
        link_keys = apply_sort(mode, results, wid, boundary)
        mode = ask_switch()
        if mode is None:
            print("Left the tabs in that order.")
            return


if __name__ == "__main__":
    main()
PY
