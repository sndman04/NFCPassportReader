#!/bin/sh
set -eu

if ! command -v rg >/dev/null 2>&1; then
  echo "privacy_scan.sh requires ripgrep (rg)." >&2
  exit 1
fi

echo "Checking for raw production diagnostics..."
if rg -n "\\bprint\\(|\\bLogger\\.|\\bos_log\\(|\\bOSLog\\(" Sources; then
  echo "Raw diagnostics found in production sources. Use typed redacted PassportReaderLogging events only." >&2
  exit 1
fi

echo "Checking for risky sinks in production sources..."
if rg -n "UIPasteboard|URLSession|FileManager\\.default\\.createFile|\\.write\\(" Sources; then
  echo "Potential persistence, clipboard, or network sink found in production sources. Review privacy impact." >&2
  exit 1
fi

echo "Checking for sensitive diagnostic vocabulary outside approved references..."
if rg -n "MRZ KEY|Kseed:|KSenc:|KSmac:|RND\\.IFD:|RND\\.ICC:|Unprotected APDU|RAPDU:|FFD8FFE0" Sources; then
  echo "Sensitive diagnostic vocabulary found in production sources." >&2
  exit 1
fi

echo "Privacy scan passed."
