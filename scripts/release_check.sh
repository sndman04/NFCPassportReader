#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export DEVELOPER_DIR
IOS_TEST_DESTINATION="${IOS_TEST_DESTINATION:-platform=iOS Simulator,name=iPhone 17,OS=26.5}"

xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
xcodebuild test -scheme NFCPassportReader -destination "$IOS_TEST_DESTINATION"
scripts/api_surface_check.sh
scripts/privacy_scan.sh
scripts/nfc_boundary_check.sh
git diff --check

if command -v rg >/dev/null 2>&1; then
  rg -n \
    "Logger\\.|os_log|print\\(|UIPasteboard|UserDefaults|URLSession|FileManager\\.default|dumpPassportData\\(|Kseed|KSenc|KSmac|RND\\.IFD|RND\\.ICC|APDU|RAPDU|FFD8FFE0" \
    Sources Tests readme.md MIGRATION_NOTARY.md THREAT_MODEL.md NFCPASSPORTREADER_FORK_SECURITY_AND_FUNCTIONALITY_PLAN.md \
    || true
else
  grep -R -n -E \
    "Logger\\.|os_log|print\\(|UIPasteboard|UserDefaults|URLSession|FileManager\\.default|dumpPassportData\\(|Kseed|KSenc|KSmac|RND\\.IFD|RND\\.ICC|APDU|RAPDU|FFD8FFE0" \
    Sources Tests readme.md MIGRATION_NOTARY.md THREAT_MODEL.md NFCPASSPORTREADER_FORK_SECURITY_AND_FUNCTIONALITY_PLAN.md \
    || true
fi

echo "Release check completed. Review expected documentation/test/type-name hits from the risky-pattern search above."
