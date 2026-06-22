#!/bin/sh
set -eu

scan() {
  pattern="$1"
  shift

  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$@"
  else
    grep -R -n -E "$pattern" "$@"
  fi
}

echo "Checking for raw production diagnostics..."
if scan "(^|[^[:alnum:]_])(print\\(|Logger\\.|os_log\\(|OSLog\\()" Sources; then
  echo "Raw diagnostics found in production sources. Use typed redacted PassportReaderLogging events only." >&2
  exit 1
fi

echo "Checking for risky sinks in production sources..."
if scan "UIPasteboard|URLSession|UserDefaults|FileManager\\.default|\\.write\\(" Sources; then
  echo "Potential persistence, clipboard, filesystem, defaults, or network sink found in production sources. Review privacy impact." >&2
  exit 1
fi

echo "Checking for sensitive diagnostic vocabulary outside approved references..."
if scan "MRZ KEY|Kseed:|KSenc:|KSmac:|RND\\.IFD:|RND\\.ICC:|Unprotected APDU|RAPDU:|FFD8FFE0" Sources; then
  echo "Sensitive diagnostic vocabulary found in production sources." >&2
  exit 1
fi

echo "Checking for removed raw import/export APIs..."
if scan "dumpPassportData\\(|UnsafePassportRawDataExporter|rawDataImportErrors|NFCPassportModel\\(from:" Sources; then
  echo "Removed raw passport import/export API found in production sources. Keep raw chip material internal only." >&2
  exit 1
fi

echo "Privacy scan passed."
