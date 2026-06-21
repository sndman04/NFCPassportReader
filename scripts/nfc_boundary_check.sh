#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

FACTORY="Sources/NFCPassportReader/NFC/PassportNFCSessionFactory.swift"

scan() {
  pattern="$1"
  shift

  if command -v rg >/dev/null 2>&1; then
    rg -n "$pattern" "$@"
  else
    grep -R -n -E "$pattern" "$@"
  fi
}

echo "Checking CoreNFC session construction boundary..."

if scan "NFCTagReaderSession[[:space:]]*\\(" Sources | grep -v "$FACTORY"; then
  echo "NFCTagReaderSession must be created only through PassportNFCSessionFactory." >&2
  exit 1
fi

if scan "NFCTagReaderSession.*queue:[[:space:]]*nil" "$FACTORY"; then
  echo "PassportNFCSessionFactory must not create CoreNFC sessions with queue: nil." >&2
  exit 1
fi

if scan "NFCTagReaderSession[[:space:]]*\\(" "$FACTORY" | grep -v "queue:[[:space:]]*delegateQueue"; then
  echo "Every NFCTagReaderSession factory initializer must pass the audited delegateQueue." >&2
  exit 1
fi

if ! scan "NFCTagReaderSession.*queue:[[:space:]]*delegateQueue" "$FACTORY" >/dev/null; then
  echo "PassportNFCSessionFactory must pass its audited delegateQueue into NFCTagReaderSession." >&2
  exit 1
fi

if ! scan "delegateQueue:[[:space:]]*DispatchQueue[[:space:]]*=[[:space:]]*\\.main" "$FACTORY" >/dev/null; then
  echo "PassportNFCSessionFactory delegateQueue must remain DispatchQueue.main for MainActor reader state." >&2
  exit 1
fi

echo "NFC boundary check passed."
