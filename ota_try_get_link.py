#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import re
import sys
import subprocess
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

URL_RE = re.compile(rb"https?://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+")
KEY_HINTS = ("ota", "update", "firmware", "fota", "systemupdate", "upgrade")

def parse_build_prop(path: str) -> Dict[str, str]:
    props: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            props[k.strip()] = v.strip()
    return props

def pick(props: Dict[str, str], keys: List[str]) -> str:
    for k in keys:
        if k in props and props[k]:
            return props[k]
    return ""

def run_google_ota_prober(fingerprint: str, probe_py: str) -> Tuple[str, Optional[str]]:
    """
    Runs google-ota-prober's probe.py if present.
    Returns (raw_output, first_url_found)
    """
    cmd = [sys.executable, probe_py, "--fingerprint", fingerprint]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    out = out.strip()

    url = None
    for line in out.splitlines():
        m = re.search(r"(https?://\S+)", line)
        if m:
            url = m.group(1).rstrip(").,;\"'")
            break
    return out, url

def iter_candidate_files(root: str) -> List[str]:
    targets: List[str] = []
    for base, _, files in os.walk(root):
        for fn in files:
            lfn = fn.lower()
            # scan likely places: apk/jar/xml/json/conf/prop plus anything named update/ota
            if any(x in lfn for x in ("ota", "update", "fota", "firmware")) or lfn.endswith((".apk", ".jar", ".xml", ".json", ".conf", ".prop", ".txt")):
                targets.append(os.path.join(base, fn))
    return targets

def extract_urls_from_file(path: str, max_bytes: int = 25_000_000) -> List[str]:
    urls: List[str] = []
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return urls
        with open(path, "rb") as f:
            data = f.read()
        for m in URL_RE.finditer(data):
            u = m.group(0).decode("utf-8", errors="ignore")
            urls.append(u)
    except Exception:
        return urls
    return urls

def normalize_url(u: str) -> str:
    # strip common trailing punctuation
    return u.strip().strip('"\';).,')
    
def is_interesting(u: str) -> bool:
    lu = u.lower()
    return any(k in lu for k in KEY_HINTS)

def safe_http_request(url: str, method: str = "HEAD", timeout: int = 12) -> Tuple[int, Dict[str, str], bytes]:
    req = urllib.request.Request(url, method=method)
    req.add_header("User-Agent", "ota-try-get-link/1.0")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        code = resp.getcode()
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read(4096) if method != "HEAD" else b""
        return code, headers, body

def try_interpret_response(url: str, code: int, headers: Dict[str, str], body: bytes) -> Optional[str]:
    ctype = (headers.get("content-type") or "").lower()
    # If it's directly a zip payload
    if "application/zip" in ctype or url.lower().endswith((".zip", ".bin", ".payload", ".img")):
        if 200 <= code < 400:
            return url

    # If it's JSON, try to pull a URL field
    if "application/json" in ctype or (body and body.strip().startswith(b"{")):
        try:
            obj = json.loads(body.decode("utf-8", errors="ignore"))
            # common fields
            for key in ("url", "ota_url", "download", "download_url", "package_url"):
                if isinstance(obj, dict) and key in obj and isinstance(obj[key], str) and obj[key].startswith("http"):
                    return obj[key]
            # lineage-style
            if isinstance(obj, dict) and "response" in obj and isinstance(obj["response"], list):
                for it in obj["response"]:
                    if isinstance(it, dict) and "url" in it and isinstance(it["url"], str) and it["url"].startswith("http"):
                        return it["url"]
        except Exception:
            pass
    return None

def build_param_variants(props: Dict[str, str]) -> Dict[str, str]:
    return {
        "fingerprint": pick(props, ["ro.product.build.fingerprint", "ro.odm.build.fingerprint", "ro.system.build.fingerprint", "ro.build.fingerprint"]),
        "device": pick(props, ["ro.product.product.device", "ro.product.device", "ro.build.product", "ro.product.system.device", "ro.product.odm.device"]),
        "model": pick(props, ["ro.product.product.model", "ro.product.model", "ro.product.system.model", "ro.product.odm.model"]),
        "build_id": pick(props, ["ro.product.build.id", "ro.odm.build.id", "ro.system.build.id", "ro.build.id"]),
        "incremental": pick(props, ["ro.product.build.version.incremental", "ro.odm.build.version.incremental", "ro.system.build.version.incremental", "ro.build.version.incremental"]),
        "android_version": pick(props, ["ro.product.build.version.release", "ro.odm.build.version.release", "ro.system.build.version.release", "ro.build.version.release"]),
    }

def url_with_params(base: str, params: Dict[str, str]) -> str:
    parsed = urllib.parse.urlsplit(base)
    q = dict(urllib.parse.parse_qsl(parsed.query))
    for k, v in params.items():
        if v:
            q[k] = v
    new_query = urllib.parse.urlencode(q)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, parsed.fragment))

def main():
    ap = argparse.ArgumentParser(description="Try to obtain OTA download link from build.prop (no GUI).")
    ap.add_argument("--build-prop", required=True, help="Path to build.prop")
    ap.add_argument("--rom-root", default="", help="Optional: root folder of extracted ROM (system/vendor/odm/product...) to scan for OTA endpoints")
    ap.add_argument("--probe-py", default="probe.py", help="Optional: path to google-ota-prober probe.py (if you want to try Google checkin)")
    ap.add_argument("--open", action="store_true", help="Open found OTA link in browser (if any)")
    ap.add_argument("--dry-run", action="store_true", help="Do not send HTTP requests; only list candidate URLs found in ROM")
    args = ap.parse_args()

    props = parse_build_prop(args.build_prop)
    info = build_param_variants(props)

    print("Fingerprint:", info["fingerprint"])
    print("Model:", info["model"])
    print("Device:", info["device"])
    print("Build ID:", info["build_id"])
    print("Incremental:", info["incremental"])
    print("Android:", info["android_version"])
    print()

    # 1) Try Google OTA prober (if present)
    if info["fingerprint"] and os.path.exists(args.probe_py):
        print("[1/2] Trying Google OTA (probe.py)...")
        out, url = run_google_ota_prober(info["fingerprint"], args.probe_py)
        print(out)
        if url:
            print("\n[OK] OTA URL (Google):", url)
            if args.open:
                import webbrowser
                webbrowser.open(url)
            return
        print("\n[INFO] Google OTA not found.\n")
    else:
        print("[1/2] Skipping Google OTA (probe.py not found or fingerprint missing).\n")

    # 2) Scan ROM for vendor endpoints and attempt requests
    if not args.rom_root:
        print("[2/2] No --rom-root provided, cannot scan vendor endpoints.")
        print("RESULT: No OTA link found.")
        return

    print("[2/2] Scanning ROM for OTA/update endpoints...")
    files = iter_candidate_files(args.rom_root)
    seen = set()
    candidates: List[str] = []

    for p in files:
        for u in extract_urls_from_file(p):
            u = normalize_url(u)
            if u and u not in seen and is_interesting(u):
                seen.add(u)
                candidates.append(u)

    if not candidates:
        print("No candidate OTA/update URLs found in ROM files.")
        print("RESULT: No OTA link found.")
        return

    print(f"Found {len(candidates)} candidate URL(s). Showing first 50:")
    for u in candidates[:50]:
        print(" -", u)

    if args.dry_run:
        print("\n[DRY-RUN] Not sending any HTTP requests.")
        return

    # Try each candidate cautiously
    params = {
        "device": info["device"],
        "model": info["model"],
        "build": info["build_id"],
        "incremental": info["incremental"],
        "fingerprint": info["fingerprint"],
        "android_version": info["android_version"],
    }

    print("\nTrying candidates (HEAD then GET) ...")
    for base in candidates:
        # Add params only if it looks like an API/check endpoint (not already a .zip)
        test_urls = [base]
        if not base.lower().endswith((".zip", ".bin", ".img")):
            test_urls.insert(0, url_with_params(base, params))

        for tu in test_urls:
            try:
                code, headers, _ = safe_http_request(tu, method="HEAD")
                # If it looks promising, GET a small body to parse JSON
                if 200 <= code < 500:
                    code2, headers2, body2 = safe_http_request(tu, method="GET")
                    found = try_interpret_response(tu, code2, headers2, body2)
                    if found:
                        print("\n[OK] OTA URL obtained:", found)
                        if args.open:
                            import webbrowser
                            webbrowser.open(found)
                        return
            except Exception:
                continue

    print("RESULT: No OTA link found (no endpoint responded with a downloadable package).")

if __name__ == "__main__":
    main()
