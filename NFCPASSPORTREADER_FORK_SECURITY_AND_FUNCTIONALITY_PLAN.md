# NFCPassportReader Fork Plan

This note captures the context needed to work on a dedicated fork of `NFCPassportReader` for the Notary Journal iOS app without needing prior chat history.

## App Context

- App repo: `/Users/dougalvey/Documents/Codex/StripePaymentForm/Notary Journal`
- Platform: iOS/iPadOS app using SwiftUI and SwiftData.
- Current passport NFC integration file: `Notary Journal/PassportNFCServices.swift`
- Current OCR/passport parsing file: `Notary Journal/IDScanServices.swift`
- Current SwiftPM dependency:
  - Package: `NFCPassportReader`
  - URL: `https://github.com/AndyQ/NFCPassportReader.git`
  - Version: `2.3.0`
  - Revision: `deec44982fa9bf2704a5f2138eb01dab7dcf9299`
  - Recorded in: `Notary Journal.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved`

## Current App Integration

The app calls the package from `NFCPassportChipReader.scan(request:)` in `Notary Journal/PassportNFCServices.swift`.

Current reader construction and scan call:

```swift
let mrzKey = try PassportChipScanner.mrzKey(for: request)
let reader = PassportReader(masterListURL: Self.masterListURL)
let passport = try await reader.readPassport(
    mrzKey: mrzKey,
    tags: [.COM, .SOD, .DG1, .DG2, .DG12, .DG14, .DG15],
    skipSecureElements: true,
    skipCA: false,
    skipPACE: false,
    useExtendedMode: true,
    customDisplayMessage: { message in
        switch message {
        case .requestPresentPassport:
            return "Hold the top of your iPhone near the passport chip."
        case .successfulRead:
            return "Passport chip read."
        default:
            return nil
        }
    }
)
```

The app converts `NFCPassportModel` into `IDScanExtraction` and uses the result to populate identity fields, chip/passive authentication statuses, and passport photo review data when available.

The app's own OCR debug log in `Notary Journal/IDScanServices.swift` only logs counts and booleans, not document values:

```swift
idScanLogger.debug(
    "Passport OCR parse. lines=... mrz=... viz=... fallback=..."
)
```

That app-side OCR log is currently acceptable from a privacy standpoint.

## Observed Problem

Runtime console logs from a real passport chip scan showed highly sensitive data emitted by the `NFCPassportReader` path, including:

- MRZ-derived access key / MRZ information.
- BAC/PACE/session key derivation details.
- APDU request and response bytes.
- Secure messaging MAC/encryption intermediate values.
- Decrypted data-group bytes.
- Passport image/photo byte chunks.
- Low-level tag/read details.

Examples observed in logs included lines like:

```text
MRZ KEY - ...
Calculate the SHA-1 hash of MRZ_information
Kseed: ...
KSenc: ...
KSmac: ...
TagReader - sending [...]
RAPDU: ...
Decrypt data of DO'87 with KSenc
Unprotected APDU: [...]
```

Treat any existing pasted or saved scan logs as sensitive identity-document data.

## Why A Fork Is Needed

The pinned `NFCPassportReader` 2.3.0 package appears to use direct `OSLog` calls internally, such as `Logger.passportReader.debug/info/error(...)`, throughout NFC session handling, BAC/PACE, tag reads, and data-group parsing.

The current package API used by the app exposes:

```swift
PassportReader(masterListURL:)
```

It does not appear to expose a reliable app-side `logLevel: .off` initializer in the pinned version. The upstream README mentions older-style verbose logging via `PassportReader(logLevel: .debug)`, but the current pinned source does not match that clean app-side control.

Therefore, the preferred remediation is to fork or vendor the package and make logging privacy-safe at the source.

## Preferred Fork Goal

Create a small, maintainable fork of `NFCPassportReader` with:

- Sensitive logging disabled by default.
- No raw passport/NFC/BAC/PACE/APDU/data-group bytes emitted to console.
- Structured, privacy-safe progress and error reporting.
- No user-facing behavior changes unless deliberately introduced.
- Compatibility with the app's current `PassportReader.readPassport(...)` usage or a clearly documented migration.

## Security-Focused Fork Changes

### 1. Disable Sensitive Logging By Default

Remove, redact, or gate all logs that contain:

- MRZ key or MRZ information.
- Passport number, date of birth, expiration date, or checksums.
- BAC/PACE keys, seed values, session keys, random challenges, MAC inputs/outputs.
- APDU request/response byte arrays.
- Secure messaging intermediate values.
- Decrypted data-group bytes.
- Passport photo/image bytes.
- Raw NFC tag object descriptions if they expose implementation details.

Safe logs should be limited to high-level operational events, for example:

- `NFC session started`
- `Tag detected`
- `PACE unavailable, falling back to BAC`
- `BAC succeeded`
- `Reading DG1`
- `Reading DG2`
- `Passive authentication succeeded`
- `Scan canceled`
- `Connection lost`

### 2. Add Explicit Logging Configuration

Add a logging configuration that defaults to off or privacy-safe:

```swift
public enum PassportReaderLogLevel {
    case off
    case error
    case info
    case debugRedacted
}
```

Potential initializer shape:

```swift
public init(
    masterListURL: URL? = nil,
    logLevel: PassportReaderLogLevel = .off,
    logger: PassportReaderLogging? = nil
)
```

Avoid any configuration that can accidentally print raw passport/chip data in normal debug builds.

### 3. Make Logging Injectable

Add a protocol-backed logger/sink so the host app can enforce its privacy policy:

```swift
public protocol PassportReaderLogging {
    func log(_ event: PassportReaderLogEvent)
}
```

Events should be typed and redacted, not arbitrary strings with byte dumps.

### 4. Sanitize Errors

Avoid returning or logging raw low-level APDU/status-word details by default. Map them to typed reader errors such as:

- `.userCanceled`
- `.nfcNotAvailable`
- `.sessionTimedOut`
- `.connectionLost`
- `.accessKeyRejected`
- `.unsupportedPassport`
- `.verificationFailed`
- `.countryCertificateUnavailable`
- `.unexpectedReadFailure`

If retaining low-level status words is needed for diagnostics, keep them internal or expose only behind an explicit privacy-review flag.

### 5. Do Not Retain Raw Data Longer Than Needed

Review `NFCPassportModel` and data-group handling to avoid retaining raw chip data after extraction/verification unless the app explicitly requests it.

The app generally needs normalized identity fields, status values, and optionally passport photo data for photo comparison. It does not need full APDU logs or most raw data-group byte dumps.

### 6. Add Privacy Tests

Add tests for the logger/redactor to ensure sensitive strings and patterns are not emitted:

- MRZ-like strings.
- Access-key strings.
- Long hex byte dumps.
- APDU patterns.
- `Kseed`, `KSenc`, `KSmac`, `RND.IFD`, `RND.ICC`.
- JPEG-like byte chunks.

## Functionality-Focused Fork Changes

These are optional but recommended if maintaining a fork.

### 1. Typed Progress Events

Expose structured progress events rather than forcing the host app to infer state from display messages.

Suggested events:

```swift
public enum PassportReaderProgressEvent {
    case waitingForPassport
    case tagDetected
    case authenticating
    case paceStarted
    case paceSucceeded
    case paceFailedFallbackToBAC
    case bacStarted
    case bacSucceeded
    case readingDataGroup(DataGroupId, progress: Double?)
    case verifyingSOD
    case verifyingDataGroups
    case complete
}
```

This would let the app show stable plain-language UI like:

- `Hold your iPhone near the passport chip.`
- `Reading passport chip...`
- `Checking passport chip data...`
- `Passport chip read.`

### 2. More Actionable Failure Reasons

Improve error mapping so the app can tell the user what to do next:

- Wrong passport number/date/expiration.
- Phone moved away.
- NFC timeout.
- Unsupported passport feature.
- Chip verification failed.
- Country certificate unavailable.
- User canceled.

This should support better app copy without exposing internal security details.

### 3. Configurable Scan Profiles

Add a first-class data-group/profile policy:

```swift
public enum PassportScanProfile {
    case identityOnly
    case identityWithPhoto
    case fullVerification
    case custom([DataGroupId])
}
```

Possible mapping:

- `identityOnly`: `.COM`, `.SOD`, `.DG1`
- `identityWithPhoto`: `.COM`, `.SOD`, `.DG1`, `.DG2`
- `fullVerification`: `.COM`, `.SOD`, `.DG1`, `.DG2`, `.DG7`, `.DG11`, `.DG12`, `.DG14`, `.DG15`

The original app request was:

```swift
[.COM, .SOD, .DG1, .DG2, .DG12, .DG14, .DG15]
```

The fork's `.fullVerification` profile now deliberately reads DG7 and DG11 as well, so signature/mark image presence and optional personal details such as place of birth can be collected when needed. Use `.custom(...)` to preserve the narrower historical set.

### 4. Retry Strategy Improvements

Add controlled retries for transient NFC failures:

- Connection lost.
- Short reads.
- Wrong length responses.
- Temporary tag response errors.

Avoid retrying cases that likely indicate bad MRZ/access key data. Return whether retry is likely to help.

### 5. Timeout Tuning

Expose configurable operation or per-stage timeouts. Large DG2/photo reads can feel stuck. The app should be able to fail with clear copy such as:

`Move your phone back to the passport and try again.`

### 6. Structured Verification Result

Return a clearer verification result object:

```swift
public struct PassportVerificationResult {
    let sodSignatureStatus: VerificationStatus
    let dataGroupHashStatus: VerificationStatus
    let documentSignerCertificateStatus: VerificationStatus
    let countrySigningCertificateStatus: VerificationStatus
    let activeAuthenticationStatus: VerificationStatus
    let chipAuthenticationStatus: VerificationStatus
}
```

The app currently maps some verification state into `IDChipAuthenticationStatus`; a structured upstream result would reduce ambiguity.

### 7. Photo Handling Controls

Let the app choose whether to decode and return the face image. If photo comparison is not required, skipping DG2 can speed up scans and reduce sensitive data exposure.

### 8. Cancellation Hygiene

Make cancellation deterministic when:

- User cancels the NFC sheet.
- The app dismisses the scan flow.
- The app backgrounds.
- The NFC session times out.
- Connection is lost.

Avoid double-resuming async continuations.

### 9. Simulator/Test Hooks

Add a protocol-backed reader interface or fixture reader so host app UI tests can exercise scan outcomes without real NFC hardware.

## Recommended Priority

Highest priority:

1. Disable/redact sensitive logs by default.
2. Add typed/sanitized errors.
3. Add typed progress events.
4. Add scan profiles or at least data-group policy helpers.

Lower priority:

1. Timeout tuning.
2. Retry metadata.
3. Broader verification result structure.
4. Test fixture reader API.

## Future Protection Backlog

This section tracks additional blue-sky protections that remain relevant to this fork's privacy, security, correctness, and Notary Journal integration goals. Items may go beyond the original logging-focused remediation, but should still preserve compatibility unless a breaking change is deliberate and documented.

Highest-value additions:

1. Add explicit sensitive-data lifetime controls so raw data groups, MRZ-derived values, passport photo bytes, cryptographic intermediates, and low-level parse buffers are released as soon as the package has produced the normalized app-facing result.
2. Split raw-data capabilities from normal app-facing APIs. Deprecated APIs such as `NFCPassportModel.dumpPassportData(...)` should become harder to call accidentally, either through an explicitly unsafe namespace, a separate exporter type, compile-time gating, or a future major-version removal.
3. Add a privacy-safe projected result model for host apps that need identity fields, optional photo data, and verification summaries without directly depending on raw `NFCPassportModel` internals.
4. Add an explicit `PassportReaderSecurityPolicy` that centralizes privacy and verification decisions such as photo access, raw export permission, logging policy, passive-authentication requirements, and chip-authentication requirements.
5. Add verification strictness modes so a caller can distinguish "read chip data" from "require passive authentication" and "require chip/active authentication when advertised".
6. Add result trust labels that summarize read and verification outcomes in a way downstream apps can use without reinterpreting low-level booleans.
7. Return safe certificate/master-list freshness metadata, such as whether a master list was present and whether signer trust could be established, without exposing certificate dumps or sensitive metadata.
8. Expand privacy-scanning into an audit-grade release gate covering sources, tests, docs, migration notes, and build logs where available.
9. Add fuzz-style/property tests for untrusted chip data parsers, especially ASN.1, TLV, DG1, DG2, COM, SOD, and SecurityInfo.
10. Maintain a private on-device interoperability matrix by country/feature class without recording real passport values.

Product and app-integration protections:

1. Provide an app-facing "do not persist" result wrapper with no `Codable` conformance and clear documentation warning against storage, upload, clipboard, and logging.
2. Harden passport photo handling with image-size limits, decode limits, and memory-pressure behavior.
3. Keep NFC sheet display copy centralized and test that low-level errors cannot leak into user-visible strings.
4. Coordinate with Notary Journal to obscure scanned identity data when the app backgrounds or appears in the app switcher.
5. Coordinate with Notary Journal on a redacted review mode that masks sensitive fields unless the user is actively reviewing them.
6. Provide suggested privacy-safe consent copy explaining that the chip scan reads identity data and may read the passport photo.

Developer and release safety:

1. Use explicit dangerous API names and doc comments for unsafe/raw operations.
2. Consider compile-time privacy defaults that make unsafe diagnostics and raw export unavailable unless deliberately enabled.
3. Add CI execution for local privacy scanning once GitHub workflow permissions allow committing workflow files.
4. Add public API compatibility tests or a small compile-only integration target for Notary Journal's intended call shape.
5. Isolate OpenSSL behind a narrow internal boundary so future crypto-backend changes are localized.
6. Add `THREAT_MODEL.md` covering sensitive assets, attacker capabilities, logging, memory retention, malformed chip data, verification trust assumptions, and app-integration risks.
7. Add a privacy-safe diagnostics summary bundle for support that includes only scan stage, package version, safe failure reason, scan profile, and verification summary.
8. Add safe verification explanation copy so apps can explain successful, partial, inconclusive, and failed verification without exposing low-level details.
9. Plan a future major-version cleanup to remove or quarantine raw byte access, stringly errors, and compatibility APIs that make unsafe use easy.

## Implementation Status

### 2026-06-20 Extended-Read Hash Mismatch Fix

Completed:

- Investigated a Passport Chip Harness result where all read data groups reported `Hash mismatch` and trust level `verification failed`.
- Root cause: the 256-byte extended READ BINARY optimization did not clamp the final read command to the remaining declared EF length. On chips that return extra bytes when the requested length extends past the file end, parsing can still succeed because the TLV length is valid, but `DataGroup.hash(...)` hashes the retained buffer including trailing bytes, causing every SOD-covered data-group hash to mismatch.
- Fixed `TagReader.selectFileAndRead(...)` so every read command, including final extended-mode chunks, is capped to the remaining file length.
- Added adjacent hardening in `DataGroup` so retained `data` is normalized to the declared TLV length even if a caller supplies trailing bytes from a fixture/import path.
- Added focused regression tests for extended read-size clamping and retained data-group byte trimming.

Verification:

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 89 tests, 0 failures.

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- External Passport Chip Harness build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project "/Users/dougalvey/Documents/Passport Chip Fork Test App/PassportChipHarness.xcodeproj" -scheme PassportChipHarness -destination generic/platform=iOS CODE_SIGNING_ALLOWED=NO build
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted scan of changed files found no new logging sinks or raw diagnostics. Hits are existing APDU type names/comments and existing cryptographic test fixtures.

Remaining follow-up:

- Re-run the on-device harness scan that produced the screenshot. Expected result: data-group hashes should match unless the passport data is genuinely tampered or SOD verification falls back to another unrelated failure.

### 2026-06-20 Notary Journal Test App Integration Pass

Completed:

- Updated the Notary Journal test app package reference from the upstream `AndyQ/NFCPassportReader` 2.3.0 remote to the adjacent local fork at `../../../Passport Chip Fork` so the app can compile against fork-only APIs during local validation.
- Removed the stale upstream `nfcpassportreader` pin from the app's `Package.resolved`; OpenSSL remains pinned.
- Updated `Notary Journal/PassportNFCServices.swift` to construct `PassportReader(masterListURL:logLevel:)` with `logLevel: .off`.
- Migrated the chip read call from the historical explicit tag list to `scanProfile: .fullVerification`, with `skipSecureElements: false`, `photoPolicy: .read`, `securityPolicy: .notaryRecommended`, `operationTimeout: 60`, and the existing safe NFC sheet copy.
- Mapped fork `NFCPassportReaderError.privacySafeFailure` values into existing app-facing `PassportChipScanError` cases so low-level reader details remain out of UI and logs.
- Switched app-facing identity-field mapping to start from `passport.identityResult` where possible, while still using the raw model only for currently required compatibility surfaces: DG12 issue date, chip/active authentication status, and transient in-memory passport photo review data.

Verification:

- `plutil -lint Notary Journal.xcodeproj/project.pbxproj` passed.
- `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcrun swift package describe --package-path "../../../Passport Chip Fork"` passed from the Notary Journal repo and confirmed the local fork manifest/products resolve.
- `git diff --check` passed for the touched Notary Journal files.
- Targeted scan of `Notary Journal/PassportNFCServices.swift` found no new logging sinks, `dumpPassportData`, APDU/key diagnostics, MRZ-key logging, or raw byte diagnostics. Remaining hits are the existing transient passport photo extraction needed for the app's review flow.

Blocked verification:

- `xcodebuild -list` and package resolution for the Notary Journal project repeatedly hung with no diagnostic output after printing the command invocation, even with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`, `-disableAutomaticPackageResolution`, and isolated DerivedData/package clone paths. The commands were manually interrupted. Full app build/test verification remains pending until Xcode project loading/package resolution completes in this environment.

Remaining follow-up:

- Run the Notary Journal app build and focused passport chip unit/UI tests once Xcode project loading is no longer hanging.
- Validate `.notaryRecommended` against real passports before relying on the stricter passive-authentication requirement in production, especially when the master list is missing or incomplete.

### 2026-06-20 Scan/Decode Performance Pass

Completed:

- Reduced DG2/photo and other data-group read round trips when callers opt into `useExtendedMode` by letting `TagReader` prefer 256-byte reads instead of the conservative 160-byte default. Existing reduction/retry behavior still falls back to 160-byte reads for passports that reject larger reads.
- Reserved the full selected-file buffer capacity before appending NFC read chunks, avoiding repeated array growth during large data-group reads.
- Removed unused secure-messaging diagnostic string assembly from APDU protect/unprotect hot paths.
- Replaced secure-messaging send-sequence-counter increment with byte arithmetic instead of hex-string conversion on every protected command/response.
- Replaced frequently used BER/byte integer helpers with direct big-endian arithmetic, avoiding string formatting/parsing in ASN.1 length, tag, and DG2 header parsing paths.
- Added a follow-up allocation pass across scan/decode hot paths:
  - Hex formatting and test/helper hex parsing now use direct byte/nibble operations with reserved output buffers instead of repeated `String(format:)`, substring indexing, and uppercasing.
  - BER length parsing now works directly on `ArraySlice<UInt8>`, removing temporary arrays in `DataGroup`, `TagReader`, `SecureMessaging`, and `SimpleASN1Node`.
  - Data-group tag-to-class/name lookups are cached instead of scanning arrays for each parsed group.
  - DG2 image-format validation now checks the image slice before copying the full photo payload into `imageData`.
  - READ BINARY offsets and secure-messaging checksum lengths now use direct byte arithmetic.
  - Tag status-word descriptions are cached instead of rebuilding the dictionary on each response error.
- Added a second cleanup pass for less obvious speed and maintainability wins:
  - Replaced simple DO wrap/unwrap helpers with direct BER-TLV byte assembly/parsing, avoiding `TKBERTLVRecord` allocation on PACE, chip-authentication, and general-authenticate command paths.
  - Hoisted DES MAC left/right key slices out of the per-block loop used by secure messaging.
  - Factored COM version parsing into a direct ASCII-decimal helper instead of temporary C-string arrays.
  - Factored DG2 fixed-width image-header integer parsing into one bounds-checked reader, removing repeated slice conversions and making offset handling easier to audit.
  - Replaced PACE and chip-authentication OID classification chains with static lookup tables for mapping type, agreement/cipher/digest algorithm, key length, and display string.
- Kept parser hardening intact while fixing synthetic DG2/DG7 fixtures whose declared lengths did not match their test payloads.
- Tightened DG2 missing-image classification so a complete face-image header with no image bytes reports `UnknownImageFormat` rather than a generic ASN.1 structure failure.
- Changed privacy-safe unexpected-error copy from `Unexpected read failure` to `Read failed` because privacy tests intentionally reject the substring `expected`.

Verification:

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 16,OS=18.3.1'
  ```

  Result: 69 tests, 0 failures.

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Xcode continued to emit the known non-source App Intents metadata warning for the XCTest bundle: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Follow-up verification on the allocation pass:

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 16,OS=18.3.1'
  ```

  Result: 87 tests, 0 failures.

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted scan of changed scan/decode files found no new logging sinks or raw byte diagnostics. Hits were limited to internal APDU/status-word code paths and comments already covered by sanitized `LocalizedError`/failure mapping.

Follow-up verification on the second cleanup pass:

- The original `iPhone 16`, iOS 18.3.1 simulator destination was unavailable in the current environment, so the full iOS simulator unit suite was run against an installed simulator:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 89 tests, 0 failures.

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.

Remaining follow-up:

- Validate `useExtendedMode` 256-byte read preference on real passports before tagging this fork, especially for DG2/photo-heavy scans and older chips. The fallback path should preserve reliability, but real chip interoperability is the only meaningful performance proof.
- Consider adding a protocol-backed mock tag reader in a future pass if we want deterministic unit coverage for NFC chunk sizing and fallback behavior without hardware.

### 2026-06-19 Blue-Sky Protection Backlog And Policy Pass

Completed:

- Added a dedicated Future Protection Backlog to this plan covering the blue-sky recommendations: sensitive-data lifetime controls, raw API quarantine, safe result projection, security policy, verification strictness, trust labels, certificate/master-list metadata, expanded privacy scanning, parser fuzzing, on-device interoperability, app-side privacy protections, dangerous API naming, compile-time privacy defaults, CI, crypto isolation, threat modeling, safe diagnostics, verification explanations, and future major-version cleanup.
- Added `PassportReaderSecurityPolicy` and `PassportVerificationRequirement`:
  - `.default` preserves source-compatible behavior.
  - `.identityOnly` disallows DG2/photo reads and raw export.
  - `.notaryRecommended` allows photo review, blocks unsafe raw export, and requires passive-authentication integrity checks when verification is attempted.
  - Reader APIs now accept `securityPolicy:` and apply it before NFC reads and after verification.
- Added `PassportIdentityResult` as an app-facing projection that intentionally omits MRZ text, raw data-group bytes, APDUs, certificates, keys, and image bytes while preserving normalized fields, verification result, trust level, certificate metadata, and data-group names.
- Added `PassportTrustLevel`, `privacySafeExplanation`, and `PassportCertificateTrustMetadata`, including whether a master list was provided during verification.
- Added `UnsafePassportRawDataExporter`, requiring an explicit `PassportReaderSecurityPolicy(allowsUnsafeRawDataExport: true)` opt-in for deliberate raw export workflows.
- Kept `NFCPassportModel.dumpPassportData(...)` deprecated for source compatibility, but routed it through an internal `unsafeDumpPassportData(...)` helper and updated docs to steer callers away from it.
- Added `PassportReaderDiagnosticsSummary` for support-safe scan metadata without identity fields, MRZ text, APDUs, certificates, keys, raw data groups, or images.
- Added `PassportReaderPrivacyCopy` with short package-owned consent and diagnostics copy.
- Added `THREAT_MODEL.md` covering sensitive assets, attacker/failure assumptions, verification trust assumptions, app-integration risks, and release checks.
- Updated README and Notary migration notes for `securityPolicy`, `.notaryRecommended`, `identityResult`, `UnsafePassportRawDataExporter`, `PassportReaderDiagnosticsSummary`, `PassportReaderPrivacyCopy`, and the threat model.
- Expanded `scripts/privacy_scan.sh` to fail on accidental legacy raw-export usage outside the deprecated compatibility declaration.
- Added focused tests for security-policy photo blocking, verification policy failure redaction, safe identity projection, unsafe raw export opt-in, safe diagnostics summaries, suggested privacy copy, and fixture-reader policy enforcement.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Broad runtime/logging/raw-export search found no new runtime traps or raw diagnostics. Hits were limited to approved typed `eventLogger.log(...)` calls, the deprecated `dumpPassportData(...)` declaration, and OpenSSL's `ASN1_TIME_print` C API name.
- `swift build` remains unsuitable in this environment for the same SwiftPM/macOS/toolchain reasons previously documented; the iOS Xcode path was used.

Remaining follow-up:

- The new `.notaryRecommended` policy should be validated with real passports before making it mandatory in Notary Journal, because passive-authentication behavior depends on master-list availability and chip/certificate interoperability.
- Sensitive-memory zeroization is still only partially addressed by safer APIs and reduced retention surfaces; Swift does not provide a complete guarantee for wiping all value copies.
- Parser fuzz/property tests, CI workflow enablement, crypto backend isolation, screenshot/background redaction, and on-device interoperability matrix remain future backlog items.

### 2026-06-19 Privacy-Safe Logging And Modernization Pass

Completed:

- Removed production `Logger.*` call sites that emitted, or made it easy to emit, MRZ-derived material, BAC/PACE/session keys, APDU bytes, secure messaging internals, decrypted data groups, certificate details, and image bytes.
- Added `PassportReaderLogLevel`, `PassportReaderLogEvent`, `PassportReaderFailureReason`, `PassportReaderSessionInvalidationReason`, and `PassportReaderLogging`.
- `PassportReader(masterListURL:)` remains source-compatible. New optional parameters are `logLevel: .off` and `logger: nil`.
- Logging is off by default. Opt-in logging emits typed, high-level, redacted events only.
- Added focused privacy tests for default-off behavior, error-level filtering, redacted event descriptions, and privacy-safe error reason mapping.
- Removed test-time crypto fixture logging.
- Removed the ad hoc ASN.1 parser `print` helper.
- Migrated avoidable OpenSSL 3 deprecated Swift call sites to EVP APIs.
- Added a tiny `OpenSSLCompat` C target for PACE generic-mapping EC/DH parameter manipulation that still requires low-level OpenSSL point/group operations. Deprecated OpenSSL calls are isolated there with local compiler pragmas instead of being exposed throughout Swift sources.
- Made `DataGroupId` `Sendable` to avoid Swift 6 sendability warnings for typed log events.
- Fixed a PACE generic-mapping ownership issue in `OpenSSLCompat` so EC groups and points are owned for the full mapped-parameter operation.
- Added `PassportReaderProgressEvent` and `PassportReaderProgressHandler` so host apps can observe structured, privacy-safe scan progress without parsing display strings or logs.
- Added `PassportScanProfile` with `.identityOnly`, `.identityWithPhoto`, `.fullVerification`, and `.custom([DataGroupId])`, plus a source-compatible `readPassport(mrzKey:scanProfile:...)` overload.
- Sanitized NFC sheet copy for low-level response errors so status words and response descriptions are not surfaced to users by default.
- Sanitized PACE authentication-token mismatch errors so token arrays are not embedded in public error descriptions.
- Added `PassportReaderFailure` and privacy-safe retry/recovery metadata for app-facing error handling.
- Added `PassportVerificationResult` and `PassportVerificationStatus` on `NFCPassportModel` to summarize passive, active, and chip authentication state without parsing individual booleans.
- Added `operationTimeout` and `cancelRead()` support so scans can be timed out or canceled deterministically while resuming the async call once.
- Added `PassportPhotoPolicy` so apps can skip DG2 even when using a broader scan profile.
- Added `PassportChipReading` and `PassportReaderFixture` so simulator/UI tests can exercise success and failure flows without real NFC hardware.
- Updated README migration examples for async `readPassport`, progress events, scan profiles, timeout/photo controls, privacy-safe failures, verification results, and fixture injection.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- The captured iOS build log had no compiler warning diagnostics.
- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- The test-build log had no source/compiler warnings. Xcode emitted one non-source App Intents metadata warning for the XCTest bundle: `Metadata extraction skipped. No AppIntents.framework dependency found.`
- `swift test` still fails at baseline in this environment because SwiftPM evaluates the iOS package against macOS while the OpenSSL dependency requires macOS 10.15. This matches the known project note and was not treated as iOS package failure.
- Targeted logging/security search found no production `Logger.*` or `print(...)` diagnostics in `Sources`.
- Remaining hits for `Kseed`, `KSenc`, `KSmac`, and related terms are code identifiers, documentation, synthetic fixtures, or negative tests, not logging calls.

Remaining follow-up:

- Confirm Notary Journal should use `.fullVerification` for the current group set or a narrower profile after app-side review.
- Run a manual on-device passport scan before tagging the fork, because PACE/BAC behavior depends on real chip interoperability.
- Build the Notary Journal app against this fork and migrate app call sites to the chosen scan profile, timeout, progress, failure, and verification-result APIs.

### 2026-06-19 Swift Modernization And Crash-Safety Pass

Completed:

- Re-audited the Swift/C boundary. The only project-owned C left is the tiny `OpenSSLCompat` shim needed for OpenSSL EC/DH parameter mapping that Swift/OpenSSL package APIs do not safely expose. No additional OpenSSL logic was moved into C.
- Removed avoidable Swift runtime traps from NFC, PACE, BAC, Secure Messaging, and security-info parsing paths:
  - Replaced PACE session-key `try!` calls with throwing propagation.
  - Replaced PACE authentication-token TLV force unwraps with guarded parsing and privacy-safe PACE errors.
  - Replaced Chip Authentication ephemeral-key force unwraps with a guarded failure path.
  - Replaced BAC MRZ-key UTF-8 optional unwrapping with `String.UTF8View`.
  - Replaced CryptoKit `fatalError` fallback branches with CommonCrypto hash implementations.
  - Replaced SecurityInfo missing-child and body-slice traps with malformed-input rejection.
  - Replaced Secure Messaging APDU construction and data force unwraps with typed errors.
  - Replaced NFC tag detection `first!` handling with explicit empty-tag rejection.
  - Replaced file-selection APDU construction force unwraps with typed APDU protection errors.
  - Replaced PACE passport public-key decode force unwraps with guarded parsing.
  - Replaced OpenSSL PEM BIO allocation force unwraps with empty-result fallbacks that match existing parse-failure behavior.
  - Replaced SOD signing-certificate `first!` extraction with a typed OpenSSL certificate error.
- Hardened Secure Messaging response parsing:
  - Rejects empty or truncated response data before indexing.
  - Validates DO'87 ASN.1 length boundaries before slicing/decrypting.
  - Validates DO'8E checksum object boundaries before slicing.
  - Fixed MAC comparison truncation to slice the computed MAC, not the received checksum.
- Added `InvalidASN1Structure` for malformed ASN.1 structures that previously could trap while reading selected files.
- Added focused Secure Messaging negative tests for malformed checksum and encrypted-data response objects.
- Updated the progress fixture test to be Swift 6 concurrency-clean by recording progress events through a small locked test helper.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- The source/compiler warning introduced by the progress fixture test was fixed. Xcode still emits its non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`
- `swift test` still fails at baseline in this environment because SwiftPM evaluates the package against macOS while the OpenSSL dependency requires macOS 10.15; this matches the project instructions and is not treated as iOS package failure.

Remaining follow-up:

- Keep the `OpenSSLCompat` C shim unless OpenSSL-Package exposes safe Swift APIs for the required PACE generic-mapping operations or the crypto backend is deliberately replaced.
- Run a manual on-device passport scan before tagging, because the hardened PACE/BAC/CA error paths need chip interoperability validation.

### 2026-06-19 Full Bug-Check And Security Review Pass

Completed:

- Ran repeated source scans from several angles: runtime traps, unchecked pointer/OpenSSL paths, array slicing, ASN.1/TLV parsing, secure messaging, logging/privacy, sensitive-string patterns, formatting, and build warnings.
- Hardened malformed ASN.1 and data-group parsing:
  - `asn1Length` now rejects empty or truncated length fields instead of indexing past the buffer.
  - `DataGroup` body/tag/value parsing now validates body and value boundaries before slicing.
  - DG1 MRZ parsing rejects short TD1/TD2/TD3 payloads before fixed-position extraction.
  - DG2 face-image parsing validates FAC headers, feature-point skips, image-info headers, and short JPEG/JPEG2000 signatures.
  - SOD parsing now bounds-checks ASN.1 item bodies and validates OCTET STRING hex before conversion.
  - COM parsing was reviewed and remains guarded by exact version-field lengths.
- Hardened cryptographic and secure-messaging failure paths:
  - OpenSSL shared-secret derivation now throws on context, peer, length, or derive failures instead of returning an empty secret.
  - PACE and Chip Authentication now fail immediately if shared-secret derivation, nonce decryption, or authentication-token MAC generation fails.
  - Chip Authentication now checks key-generation return codes and frees the ephemeral keypair.
  - BAC mutual-authentication construction now rejects empty encryption or MAC output.
  - Secure Messaging now rejects empty MAC output during protect/unprotect.
  - DES MAC now rejects short keys without trapping.
- Removed remaining easy runtime traps in shared utilities and tests:
  - `FileManager.documentDir` now has a temporary-directory fallback.
  - `hexRepToBin`, `binToHex`, `binToInt`, `unpad`, and `xor` no longer force unwrap or index mismatched input.
  - `SecurityInfo` base methods no longer trap if accidentally called.
  - Test force unwraps and forced casts were replaced with guarded assertions.
- Added focused regression tests for malformed ASN.1 lengths, malformed Secure Messaging DO'87/DO'8E/DO'99 objects, short BAC mutual-authentication responses, malformed ECDSA signatures, invalid hex parsing, empty/all-zero unpadding, and short-key DES MAC behavior.
- Documented that `NFCPassportModel.dumpPassportData(...)` returns raw sensitive data and must not be logged, persisted, uploaded, or displayed without an explicit host-app privacy policy.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `git diff --check` passed.
- Runtime-trap scan found no remaining `try!`, `as!`, `fatalError`, `preconditionFailure`, `assertionFailure`, forced `first`/`last`, or forced `baseAddress` hits in `Sources` or `Tests`.
- Logging/privacy scan found no raw `Logger`, `OSLog`, `print`, clipboard, persistence, upload, or network diagnostics in production sources. Remaining `eventLogger.log(...)` calls are typed redacted events.
- Sensitive-pattern scan found only documentation, code identifiers, or negative-test fixtures for terms such as `Kseed`, `KSenc`, `KSmac`, APDU/RAPDU, random challenges, and JPEG markers.
- `swift test` still fails at baseline in this environment because SwiftPM evaluates the package against macOS 10.13 while the OpenSSL dependency requires macOS 10.15; this matches the project instructions and is not treated as an iOS package failure.
- The only warning in the refreshed iOS verification logs is the known non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining follow-up:

- Run an on-device passport scan before tagging, especially for PACE/BAC/CA interoperability after hardened error handling.
- Consider a future deliberate API break that replaces `[UInt8]` return values from low-level crypto helpers with throwing results throughout the package. This pass guarded the current public/internal callers without broad API churn.

### 2026-06-19 External iOS Test Harness

Completed:

- Created a separate local iOS app outside this repository at `/Users/dougalvey/Documents/Passport Chip Fork Test App`.
- The app project is `PassportChipHarness.xcodeproj` and references this fork as a local Swift package via `../Passport Chip Fork`.
- The harness folder is not a git repository and is not inside the fork worktree, so it will not be included in fork commits unless copied deliberately.
- The harness exercises the current public API surface:
  - `PassportReader(masterListURL:logLevel:logger:)`
  - typed `PassportReaderLogging`
  - `PassportReaderTrackingDelegate`
  - `PassportReaderProgressHandler`
  - `readPassport(mrzKey:scanProfile:...)`
  - `readPassport(mrzKey:tags:...)`
  - `PassportScanProfile`
  - `PassportPhotoPolicy`
  - `operationTimeout`
  - `cancelRead()`
  - `PassportReaderFailure` / privacy-safe retry guidance
  - `PassportVerificationResult`
  - `PassportChipReading` and `PassportReaderFixture`
  - `overrideNFCDataAmountToRead(amount:)`
  - `passiveAuthenticationUsesOpenSSL`
  - custom NFC sheet messages
  - PACE/BAC/CA/extended-mode flags
  - optional synthetic active-authentication challenge
- The app accepts passport access-key ingredients in memory, performs NFC reads, and displays decoded scanned data to the user after success, including public `NFCPassportModel` identity fields, MRZ, optional photo/signature images, authentication statuses, verification-result statuses, data-group names, hash-match status, certificate presence, and verification errors.
- The app intentionally does not persist, export, upload, copy, or log scanned identity data. Resetting app process memory or tapping Clear drops the in-memory result references.
- Privacy check found no `print`, `Logger`/`OSLog`, `UserDefaults`, file-writing, `dumpPassportData`, clipboard, or network usage in the harness.

Verification:

- External harness iOS build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project "/Users/dougalvey/Documents/Passport Chip Fork Test App/PassportChipHarness.xcodeproj" -scheme PassportChipHarness -destination generic/platform=iOS CODE_SIGNING_ALLOWED=NO build
  ```

- The harness build log had no source/compiler warnings. Xcode emitted one non-source App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining follow-up:

- Configure a development team/signing identity in Xcode for device installation.
- Run an on-device passport scan and verify that the app screen shows expected data while Xcode console output remains free of MRZ/access-key/APDU/key/data-group/image byte dumps.

### 2026-06-19 Additional Full Bug-Check Loop

Completed:

- Re-ran the audit from additional angles: public error descriptions, CommonCrypto wrapper safety, malformed data-group length handling, OID encoding, forced unwrap/cast patterns, logging/privacy sinks, and remaining risky slicing hotspots.
- Made `NFCPassportReaderError.localizedDescription` privacy-safe by default. Internal retry logic still uses the existing low-level `value` string where needed, but app-facing localized descriptions no longer include response text, status words, expected/actual tags, PACE detail strings, nested error descriptions, APDU/RAPDU fragments, key-material-like strings, or long hex values.
- Sanitized `OpenSSLError.localizedDescription` and `PassiveAuthenticationError.localizedDescription` so ASN.1 dumps, OpenSSL reasons, certificate/parser detail, and data-group hash mismatch detail are not exposed through normal app error copy or accidental logging.
- Hardened CommonCrypto helpers:
  - AES CBC/ECB now rejects unsupported key lengths before calling `CCCrypt`.
  - DES and 3DES now reject short keys and invalid IV lengths before calling `CCCrypt`.
  - `DESDecrypt` now passes the caller-provided IV for CBC mode instead of always passing `nil`.
- Hardened OID encoding:
  - Invalid OID strings now return empty encoded bytes instead of passing nil OpenSSL objects onward.
  - Encoded ASN.1 objects are freed after use.
  - `oidToBytes(..., replaceTag: true)` now handles empty encodings without indexing into an empty array.
- Hardened base `DataGroup` parsing:
  - Empty, one-byte, and overlong-declared data groups now throw typed parse errors instead of risking invalid ranges.
  - The parser now records the declared ASN.1 body boundary and `getNextTag`/`getNextLength`/`getNextValue` respect that boundary.
  - DG11 and DG12 repeated-field loops now stop at the declared body boundary rather than the raw buffer end.
- Added focused regression tests for privacy-safe localized descriptions, secondary error redaction, invalid crypto key/IV handling, DES CBC IV behavior, invalid OID encoding, and malformed/overlong base data-group input.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `git diff --check` passed.
- Runtime-trap scan found no `try!`, forced casts, `fatalError`, precondition/assertion failures, forced `first`/`last`, or forced `baseAddress` hits in `Sources` or `Tests`.
- Logging/privacy scan found no production raw logging, print diagnostics, clipboard, persistence, upload, or network diagnostics. Remaining OSLog usage is the typed redacted sink and remains off by default unless explicitly enabled.
- The only warning in the iOS test-build output is the known non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining follow-up:

- Run an on-device passport scan before tagging. The added hardening is designed to fail closed, but real-chip PACE/BAC/CA interoperability still needs device validation.
- Consider a future API split between internal diagnostic details and public app-safe errors if downstream code needs privacy-reviewed low-level troubleshooting without relying on `localizedDescription`.

### 2026-06-19 Productization, CI, And Final Hardening Pass

Completed:

- Prepared a GitHub Actions workflow for iOS package build, iOS test build, whitespace checks, and privacy diagnostics scanning. The workflow file is not included in the pushed commit because the current GitHub token lacks `workflow` scope.
- Added reusable local privacy scanning at `scripts/privacy_scan.sh`.
- Refreshed README integration guidance so privacy-safe async APIs, scan profiles, progress events, failure mapping, fixture injection, logging defaults, and local verification commands are the primary path.
- Added `MIGRATION_NOTARY.md` with the recommended Notary Journal `.fullVerification` call shape, timeout/progress/failure handling, fixture injection, and raw-data export warning.
- Deprecated `NFCPassportModel.dumpPassportData(...)` so raw Base64 chip export is harder to use accidentally.
- Added `NFCPassportReaderError.ScanAlreadyInProgress` and made concurrent scans fail closed instead of risking continuation replacement.
- Hardened scan cancellation/completion state with a small lock-protected scan-state guard so timeout, cancellation, NFC invalidation, and completion race paths cannot double-resume the async continuation.
- Clamped finite `operationTimeout` conversion to avoid trapping on huge timeout values.
- Converted data-group retry handling away from broad `error.value` string control flow and into typed retry predicates based on error cases/status words.
- Added focused tests for scan-in-progress error redaction and typed data-group retry classification.
- Reviewed CocoaPods metadata. Swift Package Manager remains the supported integration path for this fork.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Repeated bug-check loops covered public errors/logging, async cancellation/concurrency, parser/crypto slicing hotspots, release metadata, docs/API ergonomics, risky sinks, and runtime-trap patterns.
- Runtime-trap scan found no `try!`, forced casts, `fatalError`, precondition/assertion failures, forced `first`/`last`, or forced `baseAddress` hits in `Sources` or `Tests`.
- Production privacy scan found no raw `print`, direct `Logger`, `os_log`, clipboard, network, file-write, or sensitive diagnostic phrase hits in `Sources`.
- The only warning in the final iOS test-build output is the known non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining release blockers:

- Run a manual on-device passport scan.
- Build Notary Journal against the fork/tag and confirm the chosen profile, timeout, progress, failure, and verification-result mappings.

### 2026-06-19 Repository Compaction Pass

Completed:

- Removed the bundled example app trees under `Examples/`. They were not part of the Swift package build, duplicated app-side concerns, and still contained raw `print(...)` diagnostics and raw `dumpPassportData(...)` export flows that do not match this privacy fork's default posture.
- Removed `NFCPassportReader.podspec`. Swift Package Manager is now the only supported integration path for this fork, which avoids carrying stale CocoaPods metadata and a second packaging surface around the C shim.
- Updated README copy to remove CocoaPods/sample-app references and point passive-authentication certificate setup at `scripts/README.md`.
- Audited source files for obvious dead private/internal code. No source files were removed because the remaining low-reference files are package APIs, parser subclasses, crypto helpers, or compatibility surfaces used by type/function references rather than filename.
- Removed unused private OpenSSL helpers (`pubKeyToPEM`, `privKeyToPEM`, `pkcs7DataToPEM`) and a stale `loaded` flag from `OpenSSLUtils`; current certificate/key paths use the remaining direct ASN.1 and key APIs.
- Removed the generated local `.build` directory after successful verification; SwiftPM/Xcode will recreate it when needed.

Verification:

- `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build` passed.
- `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing` passed.
- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted search found no remaining active references to the removed example app, podspec, or deleted OpenSSL helper symbols.
- The only warning in the final iOS test-build output is the known non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining follow-up:

- Consider a future major-version API break to remove raw dump import/export APIs entirely. This pass kept those deprecated compatibility surfaces because downstream users may still compile against them.

### 2026-06-19 Top-To-Bottom Edge-Case Bug Audit

Completed:

- Audited parser, NFC read-loop, scan state, SOD parsing, OpenSSL bridge, certificate wrapper, and logging-adjacent code for malformed input, invalid ranges, empty responses, concurrent calls, and C-boundary failure cases.
- Hardened DG2 image parsing so malformed ISO 19794-5 facial records with no image payload throw `UnknownImageFormat` instead of slicing at `data.endIndex`.
- Hardened SOD signature-content parsing so zero, negative, whitespace-padded, and out-of-range data-group identifiers are handled explicitly. Invalid ids now throw a passive-authentication parse error instead of indexing outside the fixed hash list.
- Hardened NFC binary reads:
  - `overrideNFCDataAmountToRead(amount:)` now clamps non-positive and oversized values into a safe APDU read-size range.
  - `selectFileAndRead` now fails closed if a read amount is non-positive or the tag returns an empty chunk, preventing zero-progress read loops.
- Fixed optional DG11/DG12 field parsing so records containing only a tag list, or only a subset of optional fields, stop cleanly at the declared body boundary instead of forcing another value read.
- Fixed a scan-concurrency state bug where a rejected concurrent scan could overwrite the active scan's passport model, MRZ key, tag list, security policy, or diagnostics callback before `ScanAlreadyInProgress` was returned.
- Hardened OpenSSL bridge edges:
  - Empty BIO output now returns an empty string without allocating an invalid buffer.
  - Empty PKCS7 certificate stacks now return an empty array instead of creating an invalid Swift range.
  - CMS verification with no returned encapsulated content now throws a typed OpenSSL error instead of constructing invalid data.
- Hardened `X509Wrapper` ownership and nil handling:
  - `X509_dup` failure now throws instead of storing a nil certificate pointer.
  - Duplicated certificates are released in `deinit`.
  - Missing certificate public-key structures now return empty key metadata instead of crossing the C boundary with nil.
- Added focused regression tests for DG2 missing image payload, SOD invalid/zero/whitespace-padded data-group ids, and absent optional DG11/DG12 fields.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted risky-pattern search found no active `try!`, forced casts, `fatalError`, precondition/assertion failures, forced `first`/`last`, forced `baseAddress`, raw `print`, direct `Logger`, or `os_log` sinks in `Sources` or `Tests`. Expected remaining hits are the deprecated raw export API declaration, typed redacted `eventLogger.log(...)` calls, and OpenSSL's `ASN1_TIME_print` API use.
- The final iOS test-build log had no warning or error lines.

Remaining follow-up:

- Run a manual on-device scan against real NFC chips before tagging, especially passports with sparse DG11/DG12 data, PACE-capable chips, and chips that return short or empty RAPDU chunks under connection stress.
- Keep `swift test` out of the release signal unless the package manifest is deliberately changed for macOS testing; the iOS/Xcode verification path remains the source of truth for this fork.

### 2026-06-19 License Compliance Check

Findings:

- Upstream `AndyQ/NFCPassportReader` is MIT licensed with `Copyright (c) 2019 Andy Qua`.
- The root `LICENSE` file is still present and preserves the upstream MIT copyright and permission notice.
- MIT redistribution requires keeping the copyright notice and permission notice in all copies or substantial portions of the software. Source releases of this fork should include the root `LICENSE`; binary/app distributions that include this package should include the same MIT notice in the app's third-party notices or acknowledgements.
- Existing source-file copyright headers for Andy Qua remain intact.
- README acknowledgements for pypassport, YobiWiki, and Marcin Krzyzanowski/OpenSSL-Universal remain present.
- The removed bundled examples included their own app/sample artifacts, but no retained production source depends on files from those example trees. No replacement notice is needed for deleted sample-only content.
- The fork depends on `OpenSSL-Package`, which distributes OpenSSL 3.x binaries under Apache-2.0. App/release notices should include the OpenSSL-Package/OpenSSL Apache-2.0 license text as part of dependency attribution.

Release checklist:

- Do not remove or rewrite the root `LICENSE` file.
- Include this package's MIT notice in any source archive, fork tag, binary SDK distribution, or app third-party notices.
- Include OpenSSL-Package/OpenSSL Apache-2.0 notices when distributing an app or binary built with this package.
- If adding new copied third-party code, add its license file or attribution before release.

### 2026-06-19 Master-List Trust Status Clarification

Decision:

- Treat country signer trust as `.notChecked` when passive authentication is attempted without a CSCA master list. This distinguishes "data integrity checked but signer trust anchor unavailable" from a real trust-chain failure.
- Keep SOD signature and data-group hash results independent so apps can safely show that chip data matched the signed SOD even when signer trust cannot be established.
- Update app-facing documentation to tell host apps not to present a missing master list as evidence that a USA or other passport failed verification.

Implementation status:

- Updated `NFCPassportModel.verificationResult.countrySigningCertificateStatus` to require both a verification attempt and a provided master list before returning pass/fail.
- Added a focused test for the no-master-list branch.
- Updated README passive-authentication guidance.

Follow-up:

- Verify on device with a configured CSCA/ICAO PKD master list so the harness can show a known-good trusted signer path as well as the no-master-list path.

## App-Side Migration Options

### 2026-06-20 Standards Coverage Hardening Pass

Completed:

- Replaced generic `NotImplementedDG` parser mapping for optional LDS data groups with typed opaque data-group classes for DG3, DG4, DG5, DG6, DG8, DG9, DG10, DG13, and DG16.
- Opaque optional groups now preserve declared body/data and report the correct `DataGroupId`, so they can be read, retained, included in passive-authentication hash checks, and deliberately exported only through the existing unsafe raw-export policy.
- Centralized DG11/DG12 LDS text decoding through `LDSStringDecoder`, preserving valid UTF-8 multilingual names, places, authorities, and observations while avoiding nil drops on malformed text bytes.
- Added `PassportPACEKeyReference` for MRZ, CAN, PIN, and PUK PACE password-reference values.
- Added source-compatible `PassportReader.readPassport(...)` overloads that let callers provide an alternate PACE credential/reference while still passing the MRZ key for BAC fallback.
- Kept PACE Integrated Mapping (IM) explicitly unsupported rather than pretending it works. This remains a standards-compliant combination that requires real cryptographic implementation and chip validation.
- Updated README support matrix and usage examples for all LDS data groups, alternate PACE credentials, and the remaining IM/CAM boundary.

Tests added:

- All previously opaque LDS data-group tags now parse to typed classes with the expected `DataGroupId`.
- DG11 multilingual UTF-8 fields cover Latin diacritics, Japanese, and Arabic text.
- DG12 multilingual UTF-8 fields cover Latin diacritics, Japanese, Spanish text, and Arabic text.
- PACE password-reference raw values are covered for MRZ, CAN, PIN, and PUK.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```
- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted risky-pattern search found no new raw logging or diagnostic sinks. Hits were limited to documentation, typed redacted logging calls, existing cryptographic code identifiers, synthetic tests, and safe API names.
- The only warning observed in the iOS test-build output was the known non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining follow-up:

- Implement and validate PACE Integrated Mapping (IM) and Chip Authentication Mapping (CAM) before claiming complete PACE coverage for every standards-compliant passport.
- Run on-device interoperability checks before tagging.
- Maintain a private real-passport interoperability matrix across BAC, PACE-GM, PACE-IM, PACE-CAM, extended-length behavior, sparse DG11/DG12, and multilingual optional text without recording real passport values.

### 2026-06-20 Standards Coverage Gap Patch

Completed:

- Preserved unrecognized DG14/CardAccess `SecurityInfo` entries as redacted `UnknownSecurityInfo` values instead of silently dropping them.
- Added `CardAccess.paceInfos` and PACE selection logic so chips advertising multiple PACE mappings use implemented GM options when available and report unsupported-only IM/CAM sets explicitly.
- Added a per-`PACEInfo` `PACEHandler` path and updated `PassportReader` to attempt advertised PACE options in an implementation-aware order.
- Added a small DER parser for structured ASN.1 nodes and switched SOD data-group hash extraction to parse the LDS Security Object directly instead of depending on OpenSSL text-dump formatting.
- Hardened SOD CMS/manual signature extraction so signer info is found structurally even when optional CMS certificate or CRL fields shift child positions.
- Changed passive-authentication signature handling to try the requested SOD verifier first, then the alternate CMS/manual verifier, before falling back to unsigned encapsulated-content extraction. If both signature verifiers fail, data-group hashes can still be compared, but `documentSigningCertificateVerified` remains false.
- Updated DG7 parsing to preserve all displayed signature/mark image items while keeping `imageData` and `signatureImage` compatible with the first image.
- Updated DG15 parsing to accept RSA and EC public keys through a generic public-key decode first, then classify the key type explicitly for Active Authentication.
- Updated README support notes for multiple DG7 images, structured SOD parsing, unknown security-info retention, PACE option selection, and the remaining IM/CAM boundary.

Tests added:

- DG7 multiple-image parsing keeps both image payloads and preserves the first-image compatibility API.
- Structured SOD LDS Security Object parsing covers data-group hash extraction and rejects invalid data-group numbers.
- PACE option ordering prefers implemented GM over an earlier unsupported mapping.
- Unknown `SecurityInfo` OIDs are retained as redacted objects.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted risky-pattern search found no new raw logging or diagnostic sinks. Hits were limited to comments/API names, typed redacted logging calls, existing cryptographic code identifiers, synthetic tests, and safe parser/error names.
- The only warning observed in the iOS test-build output was the known non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining follow-up:

- Implement and validate PACE Integrated Mapping (IM) and Chip Authentication Mapping (CAM) before claiming complete PACE coverage for every standards-compliant passport.
- Run on-device interoperability checks against real chips before tagging, especially PACE option ordering, CMS SOD variants, multiple DG7 image items, and RSA/ECDSA Active Authentication documents.

### 2026-06-20 Full Security And Edge-Case Bug Check Loop

Completed:

- Ran repeated parser, trust-state, authentication, logging, and malformed-input passes until the follow-up scans stopped producing new actionable issues.
- Extended BER/DER definite long-form length handling from two-byte lengths to one-through-four-byte length forms, so large standards-compliant data groups such as photo-heavy DG2 records are not rejected solely because they exceed 65,535 bytes.
- Kept indefinite, overlong, and out-of-range ASN.1 length forms rejected, and added matching encoding/decoding tests for three- and four-byte lengths plus malformed length encodings.
- Fixed base `DataGroup` and structured ASN.1 parsing to read the expanded length headers safely.
- Hardened DG2 image-count parsing so a malformed zero-length count throws `InvalidASN1Structure` instead of indexing into an empty value.
- Hardened structured ASN.1 INTEGER/OID helpers so negative or overflowing values fail closed instead of wrapping Swift `Int` arithmetic.
- Fixed a PACE Generic Mapping error path that could leak the OpenSSL mapping key if a later step threw before the manual free.
- Fixed passive-verification repeatability:
  - repeated `verifyPassport(...)` calls now reset errors, status booleans, parsed data-group hashes, and certificate trust material before recomputing results;
  - document/country signing certificate accessors are computed from current verification state instead of lazy-caching stale certificate objects.
- Fixed Active Authentication progress/logging so `.activeAuthenticationSucceeded` is emitted only after cryptographic verification actually sets `activeAuthenticationPassed`.

Tests added or expanded:

- ASN.1 length encoding/decoding coverage for 65,536-byte and 16,777,216-byte lengths, plus rejected indefinite/unsupported length forms.
- Base data-group parsing coverage for a three-byte long-form body length.
- DG2 malformed empty-image-count coverage.
- Structured ASN.1 negative INTEGER, overflowing INTEGER, overflowing OID arc, and large second OID arc coverage.
- Repeat passive-verification error-state coverage.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 16,OS=18.3.1'
  ```

  Result: 84 tests, 0 failures.

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted risky-pattern search found no active `try!`, forced casts, `fatalError`, precondition/assertion failures, forced `first`/`last`, forced `baseAddress`, raw `print`, direct `Logger`, or `os_log` sinks. Remaining hits were typed redacted `eventLogger.log(...)` calls and certificate/OpenSSL API names.
- Xcode continued to emit the known non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining follow-up:

- Add deterministic NFC-session seams if future work needs direct unit tests for Active Authentication event emission, PACE fallback ordering under thrown tag-reader errors, or chunk-size fallback behavior without hardware.
- Run on-device interoperability checks before tagging, especially very large DG2 records, PACE-GM passports, unsupported IM/CAM-only passports, sparse optional DG11/DG12 records, and RSA/ECDSA Active Authentication chips.

### 2026-06-20 Repository Gap Review

Reviewed scan coverage, verification semantics, privacy surfaces, logging, public APIs, tests, migration notes, and the current threat model.

Potential gaps to resolve or deliberately accept:

- `photoPolicy` and `PassportReaderSecurityPolicy.allowsPassportPhoto` only filter explicitly requested data groups. Legacy `readPassport(mrzKey:tags: [])` still flips into "read all from COM" mode after policy filtering, so a caller using `.identityOnly` security policy plus empty tags could still read DG2 if the chip advertises it. Prefer making empty tags resolve through an explicit scan profile or applying photo/security filtering again after COM expansion.
- Passive-authentication wording is still easy to overstate. `passportDataNotTampered` and `PassportVerificationResult.dataGroupHashStatus` are computed over the groups actually read, not every hash listed in SOD or every group present in COM. That is useful for minimal scans, but app copy and policy names should say "read data groups matched SOD" rather than implying the whole document was verified.
- `PassportScanProfile.fullVerification` mirrors the current Notary Journal group list but does not include DG11 or DG7. That means `placeOfBirth`, residence address, phone number, DG11 personal number, and signature/mark images remain absent unless a custom profile opts in. This may be correct for privacy, but Notary Journal should explicitly decide whether those fields are needed.
- `NFCPassportModel` remains a compatibility surface that publicly exposes sensitive fields or raw handles such as `passportMRZ`, `dataGroupsRead`, `getDataGroup(_:)`, `activeAuthenticationChallenge`, and `activeAuthenticationSignature`. `identityResult` is the safer integration path, but a future major version should quarantine or remove the raw model surface from ordinary app use.
- Chip Authentication retry state appears incomplete: `readDataGroups` creates a local `ChipAuthenticationHandler`, but does not assign it to `self.caHandler`. Later retry logic checks `self.caHandler != nil` before falling back from chip-authenticated reads, so that recovery path may never execute after successful CA. This needs an NFC seam or device validation.
- Active Authentication is only attempted when DG15 is read. Policies such as `.activeAuthenticationWhenSupported` and `.fullVerificationWhenSupported` can only know support if DG15 was requested and parsed; app profiles that omit DG15 should treat active-auth status as not checked, not unsupported.
- On-device coverage remains the main release blocker. The private interoperability matrix should cover BAC-only, PACE-GM, unsupported IM/CAM-only, CA-supported, AA RSA, AA ECDSA, very large DG2, sparse DG11/DG12, multiple DG7 images, and connection-loss/chunk fallback cases without recording real passport values.

Verification during this review:

- Read the fork plan, migration notes, threat model, scan/profile/security-policy code, model/result surfaces, logging, parser tests, and risky logging/API search output.
- Did not change production code or run a full iOS build in this pass; this was a findings review only.

### 2026-06-20 Repository Gap Fix Pass

Completed:

- Added `PassportDataGroupReadPolicy` so data-group filtering is centralized and testable.
- Re-applied photo policy after COM expansion, fixing legacy empty-tag reads that could otherwise read DG2 despite `photoPolicy: .skip` or `allowsPassportPhoto: false`.
- Made `securityPolicy: .identityOnly` plus legacy `tags: []` resolve to the minimal identity profile (`.COM`, `.SOD`, `.DG1`) instead of reading every COM-advertised group.
- Expanded `.fullVerification` to include `.DG7` and `.DG11` in addition to the previous Notary Journal set, so signature/mark image presence and optional personal details such as place of birth are collected when available.
- Preserved `self.caHandler` during Chip Authentication so data-group retry logic can detect that CA was active and re-establish BAC if a later read requires fallback.
- Tightened passive-authentication wording in README, migration notes, and trust copy to describe the groups actually read rather than implying unread optional groups were verified.
- Clarified sensitive compatibility properties on `NFCPassportModel`, while keeping source compatibility and continuing to steer apps toward `identityResult` and `verificationResult`.
- Fixed `PassportIdentityResult.hasSignatureImage` so an empty DG7 record no longer reports signature image presence.
- Prevented duplicate entries in `dataGroupsAvailable` when the same data group is added more than once.

Tests added or updated:

- `.fullVerification` now expects `.COM`, `.SOD`, `.DG1`, `.DG2`, `.DG7`, `.DG11`, `.DG12`, `.DG14`, and `.DG15`.
- Post-COM data-group policy filtering covers DG2 photo removal, DG3/DG4 secure-element removal, explicit requested-group filtering, and read-all filtering.
- Legacy empty tags with `.identityOnly` security policy resolve to the minimal identity group set.
- Empty DG7 data no longer sets `identityResult.hasSignatureImage`.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 16,OS=18.3.1'
  ```

  Result: 87 tests, 0 failures.

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted risky-pattern search found no active production raw logging, print diagnostics, direct `Logger`, `os_log`, runtime traps, clipboard, persistence, network, or accidental raw-export usage. Remaining hits were expected API names, typed redacted `eventLogger.log(...)` calls, OpenSSL API names, documentation, and negative-test fixtures.
- The only warning observed in the iOS test-build path remains the known non-source XCTest App Intents metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Second-pass residual gaps:

- Real-device interoperability remains required before tagging, especially `.fullVerification` with newly included DG7/DG11, PACE-GM, unsupported IM/CAM-only chips, Chip Authentication fallback, RSA/ECDSA Active Authentication, very large DG2, sparse DG11/DG12, and connection-loss/chunk fallback behavior.
- `NFCPassportModel` still exposes raw compatibility surfaces by design for this source-compatible fork. Future major-version cleanup should move ordinary app integrations fully to safe projected result types and quarantine raw access behind an explicitly unsafe namespace or module.
- Active Authentication support is still only knowable when DG15 is read. Profiles that omit DG15 should continue to present active authentication as not checked rather than unsupported.

### Option A: Remote Fork

Preferred long-term route:

1. Fork `https://github.com/AndyQ/NFCPassportReader.git`.
2. Apply privacy and functionality patches.
3. Tag the fork, for example `2.3.0-notary.1`.
4. Update `Notary Journal.xcodeproj/project.pbxproj` package URL to the fork.
5. Update `Package.resolved`.
6. Build and run the app.

### Option B: Local Vendored Package

Faster but heavier in this app repo:

1. Copy the package into a local directory under the Notary Journal repo.
2. Patch it locally.
3. Point SwiftPM at the local package.
4. Accept that the app repo now owns a third-party package copy.

Remote fork is cleaner for future updates. Local vendoring is useful if immediate control is needed and no fork URL is ready.

## Verification Checklist

After patching the fork and updating the app:

- Build the app target with `xcodebuild`.
- Run existing passport/NFC-adjacent tests if available.
- Run relevant UI tests for ID scan/passport scan entry points if practical.
- Manually scan a passport chip on device.
- Confirm console logs do not include:
  - MRZ key.
  - Passport number/date/expiry/checksum values.
  - APDU byte dumps.
  - BAC/PACE/session key material.
  - Decrypted data-group bytes.
  - Photo/image byte dumps.
- Confirm user-facing scan still succeeds and shows useful progress.
- Confirm cancellation and failed scans produce plain-language app messages.

## Notes

- Repo hygiene update: `.gitignore` now covers standard Swift/Xcode build artifacts, local editor/agent state, scratch directories, dependency build outputs, and sensitive local passport/NFC fixtures or downloaded certificate material. The paired Notary Journal app repo already had a `.gitignore`; it was updated only to ignore local `.claude/` agent state.
- CI workflow note: `.github/workflows/ios-package.yml` should be tracked with the fork. Its Actions trigger key is quoted as `"on"` so local YAML tooling does not misparse it as a boolean while preserving GitHub Actions behavior.
- The app must not use backend code or backend routes as a source of truth for this work.
- Preserve user privacy and avoid logging PII, ID details, signatures, thumbprints, keys, tokens, or decrypted sensitive artifacts.
- If changing returned request/response behavior or app contract mappings, review `JOURNAL_API_CONTRACT_v1.md` and related contract docs first.
