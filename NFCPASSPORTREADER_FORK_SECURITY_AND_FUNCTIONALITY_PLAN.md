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
- `fullVerification`: `.COM`, `.SOD`, `.DG1`, `.DG2`, `.DG12`, `.DG14`, `.DG15`

The current app requests:

```swift
[.COM, .SOD, .DG1, .DG2, .DG12, .DG14, .DG15]
```

Before changing behavior, confirm which groups are actually required for Notary Journal's workflow.

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

## Implementation Status

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

## App-Side Migration Options

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

- The app must not use backend code or backend routes as a source of truth for this work.
- Preserve user privacy and avoid logging PII, ID details, signatures, thumbprints, keys, tokens, or decrypted sensitive artifacts.
- If changing returned request/response behavior or app contract mappings, review `JOURNAL_API_CONTRACT_v1.md` and related contract docs first.
