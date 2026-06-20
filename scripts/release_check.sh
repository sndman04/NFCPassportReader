#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export DEVELOPER_DIR

xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
scripts/privacy_scan.sh
git diff --check

rg -n \
  "Logger\\.|os_log|print\\(|UIPasteboard|UserDefaults|URLSession|dumpPassportData\\(|Kseed|KSenc|KSmac|RND\\.IFD|RND\\.ICC|APDU|RAPDU|FFD8FFE0" \
  Sources Tests readme.md MIGRATION_NOTARY.md THREAT_MODEL.md NFCPASSPORTREADER_FORK_SECURITY_AND_FUNCTIONALITY_PLAN.md \
  || true

echo "Release check completed. Review expected documentation/test/type-name hits from the risky-pattern search above."
