#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
export DEVELOPER_DIR

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/nfcpassport-api-surface.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

write_probe_package() {
  local package_dir="$1"
  local source="$2"

  mkdir -p "$package_dir/Sources/ExternalAPISurfaceProbe"
  cat > "$package_dir/Package.swift" <<PACKAGE
// swift-tools-version:6.3

import PackageDescription

let package = Package(
    name: "ExternalAPISurfaceProbe",
    platforms: [.iOS("26.0")],
    products: [
        .library(name: "ExternalAPISurfaceProbe", targets: ["ExternalAPISurfaceProbe"])
    ],
    dependencies: [
        .package(name: "NFCPassportReader", path: "$ROOT_DIR")
    ],
    targets: [
        .target(
            name: "ExternalAPISurfaceProbe",
            dependencies: [
                .product(name: "NFCPassportReader", package: "NFCPassportReader")
            ]
        )
    ]
)
PACKAGE

  cp "$source" "$package_dir/Sources/ExternalAPISurfaceProbe/Probe.swift"
}

SAFE_SOURCE="$TMP_DIR/SafeProbe.swift"
cat > "$SAFE_SOURCE" <<'SWIFT'
import Foundation
import NFCPassportReader

@available(iOS 26, *)
public final class ProbeLogger: PassportReaderLogging {
    public init() {}

    public func log(_ event: PassportReaderLogEvent) {
        _ = event.description
    }
}

@available(iOS 26, *)
@MainActor
public func compileSafePassportReaderSurface() {
    let reader = PassportReader(logLevel: .debugRedacted, logger: ProbeLogger())
    reader.passiveAuthenticationUsesOpenSSL = false
    reader.setMasterListURL(URL(fileURLWithPath: "/tmp/masterList.pem"))
    reader.cancelRead()

    let options = PassportScanOptions(
        scanProfile: .fullVerification,
        skipSecureElements: false,
        skipCA: false,
        skipPACE: false,
        useExtendedMode: true,
        operationTimeout: 60,
        photoPolicy: .read,
        securityPolicy: .notaryRecommended,
        pacePolicy: .allowBACFallback
    )

    let failure = PassportReaderFailure(
        reason: .connectionLost,
        stage: .readingDataGroup(.DG2)
    )
    let summary = PassportReaderDiagnosticsSummary(
        scanProfile: .identityOnly,
        photoPolicy: .skip,
        failure: failure
    )
    let verification = PassportVerificationResult(
        sodSignatureStatus: .notChecked,
        dataGroupHashStatus: .notChecked,
        documentSignerCertificateStatus: .notChecked,
        countrySigningCertificateStatus: .notChecked,
        activeAuthenticationStatus: .notChecked,
        chipAuthenticationStatus: .notChecked
    )
    let revocation = PassportCertificateRevocationCheck(
        status: .notChecked,
        reason: .notImplemented
    )
    let record = PassportInteroperabilityRecord(
        issuingRegionCode: "UTO",
        chipFeatureClass: "pace-gm-synthetic",
        scanOptions: options,
        verificationResult: verification,
        trustLevel: .inconclusive,
        notes: "synthetic compatibility outcome only"
    )

    _ = reader as PassportChipReading
    _ = PassportReaderPrivacyCopy.noRawDiagnostics
    _ = PassportReaderLogEvent.readingDataGroup(.DG1).description
    _ = PassportReaderProgressEvent.readingDataGroup(.DG1, progress: nil).description
    _ = PassportScanProfile.fullVerification.dataGroups
    _ = DataGroupId.DG14.getName()
    _ = failure.recoverySuggestion
    _ = summary.dataGroupsRead
    _ = verification.overallStatus
    _ = revocation.privacySafeExplanation
    _ = record.containsOnlyNonIdentifyingFields
}
SWIFT

UNSAFE_SOURCE="$TMP_DIR/UnsafeProbe.swift"
cat > "$UNSAFE_SOURCE" <<'SWIFT'
import NFCPassportReader

@available(iOS 26, *)
public func compileUnsafePassportReaderSurface() {
    _ = NFCPassportModel()
    _ = TagReader(tag: nil)
    _ = ResponseAPDU(data: [], sw1: 0x90, sw2: 0x00)
    _ = BACHandler(tagReader: nil)
    _ = PACEHandler(tagReader: nil)
    _ = SecureMessaging(ksenc: [], ksmac: [], ssc: 0)
    _ = DataGroup(data: [])
    _ = SecurityInfo.getInstance(object: nil)
    _ = OpenSSLUtils.self
}
SWIFT

SAFE_PACKAGE="$TMP_DIR/Safe"
UNSAFE_PACKAGE="$TMP_DIR/Unsafe"
write_probe_package "$SAFE_PACKAGE" "$SAFE_SOURCE"
write_probe_package "$UNSAFE_PACKAGE" "$UNSAFE_SOURCE"

(
  cd "$SAFE_PACKAGE"
  xcodebuild \
    -scheme ExternalAPISurfaceProbe \
    -destination generic/platform=iOS \
    build >/dev/null
)

set +e
UNSAFE_OUTPUT="$(
  cd "$UNSAFE_PACKAGE" &&
    xcodebuild \
      -scheme ExternalAPISurfaceProbe \
      -destination generic/platform=iOS \
      build 2>&1
)"
UNSAFE_STATUS=$?
set -e

if [[ "$UNSAFE_STATUS" -eq 0 ]]; then
  echo "Expected unsafe external API probe to fail, but it compiled." >&2
  exit 1
fi

for symbol in NFCPassportModel TagReader ResponseAPDU BACHandler PACEHandler SecureMessaging DataGroup SecurityInfo OpenSSLUtils; do
  if ! grep -Eq "cannot find '${symbol}' in scope|cannot find type '${symbol}' in scope|initializer is inaccessible due to 'internal' protection level|'${symbol}' is inaccessible due to 'internal' protection level" <<<"$UNSAFE_OUTPUT"; then
    echo "Unsafe external API probe failed, but not because $symbol was inaccessible." >&2
    echo "$UNSAFE_OUTPUT" >&2
    exit 1
  fi
done

echo "External API surface check passed."
