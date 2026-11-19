#!/bin/bash
# Sort the Chrome "repairing" NCC tabs by far-end rack triplet, A to Z.
#
# The triplet is the three letters in the memy switch on the link
# (memy-ram-as1-1 -> RAM). Tabs with the same triplet keep their order.
# The block is every NCC link tab between a divider named "repairing"
# and the next divider. Those tabs are reopened in the new order, so they reload.
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
import sqlite3
import subprocess
import sys
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

NCC = "https://ncc.ts.int-x.ai/graphql"
LINK_MARK = "/network-entity/link/"
DRY = "--dry-run" in sys.argv[1:]


def die(msg):
    print(msg, file=sys.stderr)
    raise SystemExit(1)


def chrome_tabs():
    if subprocess.run(["pgrep", "-x", "Google Chrome"], stdout=subprocess.DEVNULL).returncode != 0:
        die("Google Chrome is not running. Open the repairing tabs first.")
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
        die(exc.stderr.decode(errors="replace").strip() or "Could not read Chrome tabs.")
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


def repairing_block(windows):
    found = []
    for wid, tabs in windows.items():
        for i, tab in enumerate(tabs):
            if (divider_name(tab["url"]) or "").lower() != "repairing":
                continue
            end = next((j for j in range(i + 1, len(tabs)) if divider_name(tabs[j]["url"])), None)
            block = tabs[i + 1:end] if end is not None else []
            # Stop the block at the first non-link if there is no closing divider.
            if end is None:
                block = []
                for tab2 in tabs[i + 1:]:
                    if link_parts(tab2["url"]) is None:
                        break
                    block.append(tab2)
            if block:
                found.append((wid, tabs[i], tabs[end] if end is not None else None, block))
    if not found:
        die('No "repairing" section found. Put a tab divider named repairing before the AS-T1 links and another divider after them.')
    if len(found) > 1:
        die('More than one "repairing" section is open. Close the extra one and run this again.')
    wid, start, end, block = found[0]
    stray = [t for t in block if link_parts(t["url"]) is None]
    if stray:
        die("The repairing section has a tab that is not an NCC link. Move that tab outside the dividers and run this again.")
    return wid, start, end, block


def chrome_key():
    try:
        password = subprocess.check_output(
            ["security", "find-generic-password", "-w", "-s", "Chrome Safe Storage", "-a", "Chrome"],
            text=True, stderr=subprocess.PIPE,
        ).strip().encode()
    except subprocess.CalledProcessError:
        die("Keychain did not give Chrome Safe Storage. Approve the prompt, or open Keychain Access and allow it, then run this again.")
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
    die("No NCC login cookie in Chrome. Open https://ncc.ts.int-x.ai and sign in, then run this again.")


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


def lookup(cookie, device, iface):
    query = """query ($device: String!, $interface: String!) {
      networkDevice(device: $device) {
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
    ports = ((data.get("data") or {}).get("networkDevice") or {}).get("ports") or []
    remote = None
    for port in ports:
        link = (port or {}).get("link") or {}
        if link.get("remote_uuid"):
            remote = link["remote_uuid"]
            break
    code = choose_triplet(device, remote)
    if not code:
        return {"error": f"{device} {iface}: no rack triplet (remote {remote or 'unknown'})"}
    return {"triplet": code, "remote": remote}


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
    if startIdx is 0 then error "repairing tabs are gone"
    set lastIdx to startIdx + COUNT - 1
    if lastIdx > n then error "repairing tabs moved"
CHECKS
    set insertAt to lastIdx + 1
    if insertAt > (count of tabs of w) then
INSERT_END
    else
      if BOUNDARY is not "" then
        if (id of tab insertAt of w as text) is not BOUNDARY then error "the divider after repairing moved"
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


def main():
    windows = chrome_tabs()
    wid, _start, end, block = repairing_block(windows)
    print(f'Reading {len(block)} repairing tabs...', flush=True)
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

    results = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        results.extend(pool.map(run, jobs))
    errors = [r["error"] for r in results if r.get("error")]
    if errors:
        print("\n".join(errors[:12]), file=sys.stderr)
        die(f"Could not read a rack triplet for {len(errors)} tab(s). No tabs were moved.")
    ordered = sorted(results, key=lambda r: r["triplet"])
    counts = Counter(r["triplet"] for r in ordered)
    summary = ", ".join(f"{name} x{counts[name]}" for name in sorted(counts))
    print(summary)
    already = [r["tab"]["tid"] for r in results] == [r["tab"]["tid"] for r in ordered]
    if already:
        print("Already alphabetical. No tabs moved.")
        return
    print(f"Reordering {len(block)} tabs. They will reload.")
    if DRY:
        print("Dry run. No tabs moved.")
        return
    print("Ctrl-C in the next 3 seconds to cancel.", flush=True)
    time.sleep(3)
    reorder(
        wid,
        [r["tab"]["tid"] for r in results],
        [r["tab"]["url"] for r in ordered],
        end["tid"] if end else "",
    )
    print("Done. Walk the repairing tabs left to right.")


if __name__ == "__main__":
    main()
PY
