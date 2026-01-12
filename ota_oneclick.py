#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
import webbrowser

URL_RE = re.compile(r"(https?://\S+)")

def run_probe(fingerprint: str) -> str:
    # เรียก probe.py ของ repo เดิม แล้วเก็บ stdout กลับมา
    cmd = [sys.executable, "probe.py", "--fingerprint", fingerprint]
    p = subprocess.run(cmd, capture_output=True, text=True)
    out = (p.stdout or "") + "\n" + (p.stderr or "")
    return out.strip()

def extract_first_url(text: str) -> str | None:
    for line in text.splitlines():
        m = URL_RE.search(line)
        if m:
            # ตัดเครื่องหมายจบประโยค/วงเล็บออกแบบหยาบ ๆ
            url = m.group(1).rstrip(").,;\"'")
            return url
    return None

def main():
    ap = argparse.ArgumentParser(description="One-click OTA URL fetcher using google-ota-prober (probe.py).")
    ap.add_argument("--fingerprint", required=True, help="Full Android build fingerprint (quote it).")
    ap.add_argument("--no-open", action="store_true", help="Do not auto-open browser.")
    args = ap.parse_args()

    output = run_probe(args.fingerprint)
    print(output)

    url = extract_first_url(output)
    if not url:
        print("\n[INFO] No URL found in output.")
        sys.exit(2)

    print(f"\n[OK] OTA URL obtained: {url}")
    if not args.no_open:
        print("[INFO] Opening in default browser...")
        webbrowser.open(url)

if __name__ == "__main__":
    main()
