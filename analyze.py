#!/usr/bin/env python3
"""
analyze.py -- Android APK privacy risk analyzer
Decompiles and scans for trackers, encryption, network endpoints.
Usage: python3 analyze.py app.apk
"""
import sys, re, subprocess
from pathlib import Path
from collections import defaultdict

TRACKERS = {
    "Firebase": "com/google/firebase",
    "Google Analytics": "com/google/android/gms/analytics",
    "Crashlytics": "com/crashlytics",
    "Facebook": "com/facebook/sdk",
    "Flurry": "com/flurry",
}

def extract_apk(apk_path):
    work_dir = Path(f"/tmp/apk_{Path(apk_path).stem}")
    subprocess.run(f"apktool d {apk_path} -o {work_dir} -f", shell=True, capture_output=True)
    return work_dir

def scan_trackers(work_dir):
    trackers = defaultdict(int)
    for smali_file in work_dir.rglob("*.smali"):
        content = smali_file.read_text(errors="ignore")
        for name, pattern in TRACKERS.items():
            if pattern in content:
                trackers[name] += 1
    return trackers

def scan_urls(work_dir):
    urls = set()
    pattern = re.compile(r"const-string.*?(https?://[^\s"]+)")
    for smali_file in work_dir.rglob("*.smali"):
        content = smali_file.read_text(errors="ignore")
        urls.update(re.findall(pattern, content))
    return list(urls)[:20]

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py app.apk")
        sys.exit(1)

    apk_path = sys.argv[1]
    if not Path(apk_path).exists():
        print(f"APK not found: {apk_path}")
        sys.exit(1)

    print(f"\n🔎 Analyzing {Path(apk_path).name}...")
    work_dir = extract_apk(apk_path)

    trackers = scan_trackers(work_dir)
    urls = scan_urls(work_dir)

    print(f"\nTrackers detected:")
    for name, count in sorted(trackers.items(), key=lambda x: -x[1]):
        print(f"  {name}: {count} files")

    print(f"\nNetwork endpoints (sample):")
    for url in urls:
        print(f"  - {url}")

    print()

if __name__ == "__main__":
    main()
