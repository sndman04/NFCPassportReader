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

### 2026-06-20 Expanded Passport-Chip Hardening Backlog

This backlog turns the latest repository audit into implementable work. The items are intentionally broader than the original logging remediation and should be handled without breaking existing `NFCPassportModel` call sites unless a future major version deliberately removes compatibility APIs.

Privacy-first result and lifetime controls:

1. Add a first-class privacy-preserving read API, such as `PassportReader.readPassportIdentity(...)`, that returns only `PassportIdentityResult` and never hands the caller an `NFCPassportModel`.
2. Add a non-raw `PassportChipReadResult` wrapper for apps that need identity, verification, trust level, certificate/master-list metadata, optional explicitly requested face-image bytes, and safe diagnostics in one value. This type must not expose raw data groups, MRZ text, APDUs, keys, certificates, or active-authentication challenge/signature bytes, and it should not conform to `Codable`.
3. Add explicit sensitive-data cleanup on `NFCPassportModel` for callers that still receive the compatibility model. Cleanup should clear raw data groups, parsed hash values, card-access data, certificate objects, and active-authentication challenge/signature bytes after the caller has projected the values it needs.
4. Document that cleanup is best-effort because Swift value copies and framework internals cannot guarantee complete memory zeroization.
5. Add tests proving cleanup removes raw export material and that the privacy-first read path returns identity data without leaving raw groups accessible to the caller.

Verification and trust semantics:

1. Extend `PassportVerificationResult` with safe per-check details. Keep the existing simple `PassportVerificationStatus` properties for source compatibility, but add detail fields that distinguish: not requested, not supported/advertised, missing required data group, missing master list, signer untrusted, SOD signature failed, data-group hash mismatch, skipped by caller policy, attempted and failed, and passed.
2. Track verification issues as typed, privacy-safe values rather than requiring apps to parse `Error.localizedDescription`.
3. Report whether each read data group was covered by the SOD hashes, whether a SOD hash was present for a group that was not read, and whether COM advertised a group that was skipped, blocked by policy, unsupported, or failed to read.
4. Keep app-facing trust labels conservative: chip-read success must not imply authenticity, passive-authentication success must not imply country signer trust unless a master list was provided and validation passed, and chip/active authentication should distinguish advertised-but-skipped from attempted-and-failed.
5. Add tests for master-list missing, SOD missing, hash mismatch, signer-trust not checked, chip/active authentication not advertised, advertised-but-not-attempted, and failed verification policy.

Master-list and certificate lifecycle:

1. Add safe master-list metadata: whether a master list was configured, whether it was reachable/readable, whether a signer chain was found, and optionally the file age or modified date if available.
2. Do not expose certificate subject/issuer dumps or serial numbers by default. If future support workflows need certificate identifiers, expose only redacted/fingerprinted metadata after a privacy review.
3. Treat revocation checking as not implemented unless a tested CRL/master-list revocation workflow is added. Surface this as safe metadata rather than silently implying revocation was checked.

Photo, image, and parser hardening:

1. Bound DG2 and DG7 image byte retention with explicit maximum byte limits and safe parse failures.
2. Bound declared image dimensions and feature-point counts so malformed DG2 payloads cannot trigger excessive memory use, integer overflow, or large skips.
3. Validate image headers before copying image payloads and avoid decoding images unless the caller requests image access.
4. Add parser tests for truncated TLVs, impossible ASN.1 lengths, nested-length inconsistencies, invalid OIDs, malformed SOD hash structures, oversized DG2 image payloads, excessive DG2 dimensions, and malformed DG7 image items.
5. Add a fuzz/property-test scaffold using only synthetic data so future parser mutations can be exercised without real passport fixtures.

Policy and scan ergonomics:

1. Add preset strict scan options that bind scan profile, PACE/BAC behavior, secure-element policy, photo policy, timeout, and verification requirement together so apps do not accidentally combine incompatible flags.
2. Add PACE policy controls for practical fallback, PACE-required-when-advertised, and external CAN/PIN/PUK credential flows where the host app supports them.
3. Add clearer retry metadata by stage: waiting, connecting, PACE, BAC, data-group read, active authentication, chip authentication, passive authentication, and security-policy validation.
4. Add tests that cancellation, timeout, connection loss, and double invalidation resume the async scan exactly once.

Release, CI, and real-device validation:

1. Add an iOS CI/release checklist that runs the iOS package build, iOS test build or simulator tests, `scripts/privacy_scan.sh`, `git diff --check`, risky logging/raw export searches, and documentation checks.
2. Keep `swift test` marked as unsuitable unless the package manifest is deliberately changed to support macOS testing with the OpenSSL dependency.
3. Maintain a private on-device interoperability matrix by country/feature class without retaining real passport values, MRZ text, certificate dumps, images, or APDU logs.
4. Validate the 256-byte extended-read path, strict Notary policy, PACE fallback behavior, DG2 image handling, chip authentication, and active authentication on physical passports before tagging a release.

## Implementation Status

### 2026-06-20 Privacy-First Result And Verification Detail Pass

Completed:

- Added an expanded implementable hardening backlog covering privacy-first result APIs, sensitive-data cleanup, richer verification semantics, master-list metadata, parser/image hardening, scan presets, release checks, and real-device validation requirements.
- Added `PassportChipReadResult` and `PassportReader.readPassportIdentity(...)` so host apps can receive normalized identity, verification, trust, certificate/master-list metadata, and safe diagnostics without receiving the raw `NFCPassportModel` compatibility object.
- Added `NFCPassportModel.removeSensitiveDataForPrivacy()` to clear raw data groups, parsed hashes, card-access data, certificate objects, and active-authentication challenge/signature bytes after callers project the values they deliberately need. This is documented as best-effort minimization rather than guaranteed zeroization.
- Extended `PassportVerificationResult` with source-compatible simple statuses plus safe detail fields and data-group coverage summaries. Detail reasons distinguish not requested, not supported, skipped, missing SOD, missing master list, signer untrusted, invalid signature, hash mismatch, malformed SOD, unsupported algorithm, attempted failure, and passed without exposing raw hashes, certificates, APDUs, keys, or image bytes.
- Added safe master-list metadata on the model and certificate-trust metadata, including a local master-list modification date when available and an explicit `revocationCheckPerformed` flag that remains false until a tested revocation workflow exists.
- Added `PassportScanOptions` with reviewed `.notaryStrict`, `.identityOnly`, and `.defaultCompatibility` presets that bind scan profile, secure-element behavior, PACE/CA flags, extended mode, timeout, photo policy, and security policy into coherent configurations.
- Hardened DG2 and DG7 image parsing with explicit byte, dimension, feature-point, and total image retention bounds before retaining image payloads or allowing decode.
- Updated README, Notary migration notes, and threat model with `readPassportIdentity`, `PassportChipReadResult`, scan presets, verification detail semantics, sensitive cleanup, image bounds, and remaining real-device validation requirements.
- Added focused tests for verification details, scan presets, privacy-first result shape, sensitive cleanup, and malformed DG2 image metadata.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 102 tests, 0 failures.

- iOS package test build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted risky-pattern search found no new active production raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or accidental raw-export usage. Remaining hits are expected typed redacted events, APDU/key type names and comments, approved unsafe export internals, documentation references, and negative-test fixtures.
- Xcode still emits the known non-source XCTest App Intents metadata warning during test-build: `Metadata extraction skipped. No AppIntents.framework dependency found.`

Remaining follow-up:

- Real-passport validation is still required before tagging: `.notaryStrict`, PACE fallback behavior, 256-byte extended reads, DG2 photo handling, chip authentication, active authentication, and master-list-dependent trust behavior cannot be fully proven with local synthetic tests.
- Revocation checking remains explicitly not implemented and should not be implied in app copy or support diagnostics.

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

### 2026-06-21 Passport Chip Harness Current-Tag Update

Completed:

- Updated the external Passport Chip Harness test app at `/Users/dougalvey/Documents/Passport Chip Fork Test App` to build against the adjacent fork at tag `notary-2.3.1-privacy.3`.
- Raised the harness iOS deployment target to 26.0 to match the current fork package platform declaration.
- Updated the harness scan path from internal compatibility surfaces (`NFCPassportModel`, tracking delegate, raw-model read methods, unsafe raw exporter probe, and NFC read-size override) to the current public privacy-safe APIs: `readPassportIdentity(...)`, `PassportScanOptions`, `PassportChipReadResult`, `PassportIdentityResult`, typed logs, progress events, diagnostics summary, trust metadata, and optional face-image result.
- Kept explicit data-group testing through `PassportScanProfile.custom(...)`; the harness now labels the NFC read-size override as unavailable because it is not public in this tag.
- Added the missing `AccentColor` asset so Xcode no longer warns about the configured accent color.
- Updated the harness README with the current tag, iOS 26.0 requirement, public API coverage, and removed/internal API notes.

Verification:

- Harness iOS build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project "/Users/dougalvey/Documents/Passport Chip Fork Test App/PassportChipHarness.xcodeproj" -scheme PassportChipHarness -destination generic/platform=iOS -derivedDataPath "/Users/dougalvey/Documents/Passport Chip Fork Test App/.codex-deriveddata" CODE_SIGNING_ALLOWED=NO build
  ```

- Build output still includes the known non-source Xcode metadata warning: `Metadata extraction skipped. No AppIntents.framework dependency found.`
- Harness `git diff --check` passed, project/JSON metadata validation passed, and targeted risky-pattern search over changed harness files found no new logging sinks, raw export calls, APDU/key diagnostics, persistence, clipboard, or network use. Remaining hits were expected README privacy wording, the UI row stating MRZ is not exposed by the privacy-safe result, and explicit in-memory `faceImageData` display handling for the requested photo policy.

Remaining follow-up:

- Run the harness on an NFC-capable iPhone with a valid signing identity and real passports to validate `.fullVerification`, custom data-group reads, PACE fallback, passive-authentication results, optional bundled master-list behavior, and DG2 face-image handling.

### 2026-06-21 NFC Delegate Queue Crash Fix

Completed:

- Investigated a harness crash at NFC read start showing `_dispatch_assert_queue_fail` on a CoreNFC-related background queue.
- Root cause: `PassportReader` is main-actor isolated, but `NFCTagReaderSession` was created without an explicit delegate queue. On device, CoreNFC delivered delegate callbacks on a private serial queue, which violated the reader's main-actor/main-queue assumptions as soon as NFC detection began.
- Fixed `PassportReader` to create `NFCTagReaderSession` with `queue: .main`, keeping CoreNFC delegate callbacks on the same queue as the main-actor reader state.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- External Passport Chip Harness build succeeded against the local fork:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project "/Users/dougalvey/Documents/Passport Chip Fork Test App/PassportChipHarness.xcodeproj" -scheme PassportChipHarness -destination generic/platform=iOS -derivedDataPath "/Users/dougalvey/Documents/Passport Chip Fork Test App/.codex-deriveddata" CODE_SIGNING_ALLOWED=NO build
  ```

Remaining follow-up:

- Re-run the harness on device and confirm NFC tag detection no longer trips the dispatch queue assertion. The local environment cannot exercise physical CoreNFC scans.

### 2026-06-21 Delegate And Actor Boundary Follow-Up Audit

Completed:

- Ran a targeted scan for other CoreNFC delegate queue, actor-isolation, continuation, unstructured-task, and unsafe CoreNFC boundary patterns after the harness `_dispatch_assert_queue_fail` crash fix.
- Confirmed the only production framework external delegate conformance is `PassportReader : @preconcurrency NFCTagReaderSessionDelegate`, and the only `NFCTagReaderSession` construction now explicitly uses `queue: .main`.
- Reviewed the active scan continuation path. The continuation is still protected by `scanStateLock` and consumed through `takeActiveScanContinuation()` before resume, so cancellation, timeout, session invalidation, and scan completion do not introduce an obvious double-resume path.
- Reviewed `TagReader`, `BACHandler`, `PACEHandler`, and `ChipAuthenticationHandler` for similar delegate callback surfaces. They do not own external delegate queues; CoreNFC calls are reached through the reader-driven scan flow.
- Hardened `PassportReader.startTimeoutTask(...)` so the timeout task explicitly runs on `@MainActor` before it calls `failActiveScan(...)`. This keeps timeout-driven invalidation on the same actor as the CoreNFC delegate state instead of relying only on inherited actor context.

Verification:

- No remaining `queue: nil` CoreNFC session construction was found.
- `git diff --check` passed.
- `scripts/privacy_scan.sh` passed.
- Required generic iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 148 tests, 0 failures.

- External Passport Chip Harness build passed against the local fork:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project "/Users/dougalvey/Documents/Passport Chip Fork Test App/PassportChipHarness.xcodeproj" -scheme PassportChipHarness -destination generic/platform=iOS -derivedDataPath "/Users/dougalvey/Documents/Passport Chip Fork Test App/.codex-deriveddata" CODE_SIGNING_ALLOWED=NO build
  ```

- Targeted risky-pattern search found only expected privacy negative tests, typed APDU/key internals, safe typed event logging, and documentation/comments. No new raw diagnostic sink was added.
- Xcode still emits known non-source notes/warnings while processing the remote OpenSSL binary artifact and harness AppIntents metadata. These are external/build-system metadata messages, not warnings from changed fork source.

Remaining follow-up:

- Re-run the harness on an NFC-capable iPhone with a real passport to confirm the physical CoreNFC tag-detection path no longer crashes and that timeout/cancel/error invalidation still updates the UI cleanly.

### 2026-06-21 NFC Boundary Release Guardrail

Completed:

- Added `PassportNFCSessionFactory` as the single internal construction point for `NFCTagReaderSession`.
- Kept the audited CoreNFC delegate queue decision inside the factory: `delegateQueue` is `DispatchQueue.main`, matching the main-actor-isolated `PassportReader` state.
- Updated `PassportReader` to request sessions through the factory instead of calling the CoreNFC initializer directly.
- Added `scripts/nfc_boundary_check.sh` to fail release verification if production source creates `NFCTagReaderSession` outside the factory, if the factory uses `queue: nil`, or if the audited delegate queue stops being `.main`.
- Wired the NFC boundary check into `scripts/release_check.sh`, and documented the guardrail in `README.md` and `REPOSITORY_STRUCTURE.md`.

Verification:

- `scripts/nfc_boundary_check.sh` passed.
- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Required generic iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 148 tests, 0 failures.

- Consolidated release check passed, including iOS build, iOS build-for-testing, API surface probe, privacy scan, NFC boundary check, whitespace check, and risky-pattern report:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

- External Passport Chip Harness build passed against the local fork:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project "/Users/dougalvey/Documents/Passport Chip Fork Test App/PassportChipHarness.xcodeproj" -scheme PassportChipHarness -destination generic/platform=iOS -derivedDataPath "/Users/dougalvey/Documents/Passport Chip Fork Test App/.codex-deriveddata" CODE_SIGNING_ALLOWED=NO build
  ```

- Xcode still emits known non-source metadata notes for the remote OpenSSL binary artifact and the harness AppIntents processor. No warnings came from changed fork source.

Remaining follow-up:

- Keep the physical-device harness NFC smoke test as the final check before publishing app-consumption tags. The static guard prevents the exact queue-regression shape, but it does not replace real CoreNFC interoperability testing.

### 2026-06-21 NFC Boundary Bug-Check Pass

Completed:

- Re-reviewed the NFC boundary guardrail and surrounding reader session startup, cancellation, timeout, invalidation, and continuation-resume paths for edge-case and interruption handling.
- Fixed an edge case where `PassportNFCSessionFactory.makeTagReaderSession(...)` could return `nil`; `PassportReader` now fails the active scan immediately with a privacy-safe unexpected-read error instead of leaving the continuation pending until timeout, or indefinitely when no timeout was configured.
- Changed session startup to hold a non-optional local `readerSession` before assigning it and calling `begin()`, making the startup path deterministic.
- Re-tested `scripts/nfc_boundary_check.sh` on both the normal `rg` path and the fallback `grep` path. The first fallback check failed because its regex was too strict for portable ERE matching; simplified the patterns so minimal environments run the guard correctly.
- Tightened the factory check so every `NFCTagReaderSession` initializer in the factory must pass `queue: delegateQueue`, preventing a future second initializer from bypassing the audited queue while another good initializer keeps the script green.
- Confirmed cancellation, timeout, did-invalidate, multiple-tag, invalid-tag, connection-loss, and successful-read paths still converge through `failActiveScan(...)`, `completeActiveScan(...)`, or the intentional post-success invalidation suppression, each of which clears timeout/state or avoids double-resuming the continuation.

Verification:

- `scripts/nfc_boundary_check.sh` passed with `rg`.
- `PATH=/usr/bin:/bin:/usr/sbin:/sbin scripts/nfc_boundary_check.sh` passed, exercising the fallback `grep` path.
- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Required generic iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 148 tests, 0 failures.

- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

- External Passport Chip Harness build passed against the local fork:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project "/Users/dougalvey/Documents/Passport Chip Fork Test App/PassportChipHarness.xcodeproj" -scheme PassportChipHarness -destination generic/platform=iOS -derivedDataPath "/Users/dougalvey/Documents/Passport Chip Fork Test App/.codex-deriveddata" CODE_SIGNING_ALLOWED=NO build
  ```

- Xcode still emits the known non-source OpenSSL binary-artifact note and harness AppIntents metadata warning. No warnings came from changed fork source.

Remaining follow-up:

- Real-device harness testing remains required for physical NFC interruptions such as removing the phone from the chip during connect/read and user/system cancellation while CoreNFC is presenting its sheet.

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
- Added `PassportIdentityResult` as an app-facing projection that intentionally omits MRZ text, raw data-group bytes, APDUs, certificates, keys, and image bytes while preserving normalized fields, verification result, trust level, certificate metadata, and data-group names. Face-image bytes now live only on `PassportChipReadResult.faceImageData` when the effective photo policy is `.read`.
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
  - `hexRepToBin`, `binToHex`, `binToInt`, `unpad`, and `xor` no longer force unwrap or index mismatched input.
  - Historical note: `FileManager.documentDir` previously had a temporary-directory fallback, but the unused helper was removed on 2026-06-21 to avoid retaining a production filesystem convenience API.
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
- Historical note: this pass kept PACE Integrated Mapping (IM) explicitly unsupported rather than pretending it worked. This was superseded by the later 2026-06-20 PACE Integrated Mapping pass; real-chip validation still remains.
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

- PACE Integrated Mapping (IM) and Chip Authentication Mapping (CAM) now have implementation coverage in later 2026-06-20 passes; real-chip validation remains required before claiming complete PACE coverage for every standards-compliant passport.
- Run on-device interoperability checks before tagging.
- Maintain a private real-passport interoperability matrix across BAC, PACE-GM, PACE-IM, PACE-CAM, extended-length behavior, sparse DG11/DG12, and multilingual optional text without recording real passport values.

### 2026-06-20 Standards Coverage Gap Patch

Completed:

- Preserved unrecognized DG14/CardAccess `SecurityInfo` entries as redacted `UnknownSecurityInfo` values instead of silently dropping them.
- Added `CardAccess.paceInfos` and PACE selection logic so chips advertising multiple PACE mappings use implemented GM options when available and report then-unimplemented IM/CAM-only sets explicitly. This historical limitation was later narrowed by the PACE-IM and PACE-CAM implementation passes.
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
- PACE option ordering originally preferred implemented GM over an earlier unsupported mapping. Later PACE-IM/PACE-CAM work added implemented alternatives, while retaining real-chip validation as the release blocker.
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

- PACE Integrated Mapping (IM) and Chip Authentication Mapping (CAM) now have implementation coverage in later 2026-06-20 passes; real-chip validation remains required before claiming complete PACE coverage for every standards-compliant passport.
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
- Run on-device interoperability checks before tagging, especially very large DG2 records, PACE-GM/PACE-IM/PACE-CAM passports, sparse optional DG11/DG12 records, and RSA/ECDSA Active Authentication chips.

### 2026-06-20 Repository Gap Review

Reviewed scan coverage, verification semantics, privacy surfaces, logging, public APIs, tests, migration notes, and the current threat model.

Potential gaps to resolve or deliberately accept:

- `photoPolicy` and `PassportReaderSecurityPolicy.allowsPassportPhoto` only filter explicitly requested data groups. Legacy `readPassport(mrzKey:tags: [])` still flips into "read all from COM" mode after policy filtering, so a caller using `.identityOnly` security policy plus empty tags could still read DG2 if the chip advertises it. Prefer making empty tags resolve through an explicit scan profile or applying photo/security filtering again after COM expansion.
- Passive-authentication wording is still easy to overstate. `passportDataNotTampered` and `PassportVerificationResult.dataGroupHashStatus` are computed over the groups actually read, not every hash listed in SOD or every group present in COM. That is useful for minimal scans, but app copy and policy names should say "read data groups matched SOD" rather than implying the whole document was verified.
- `PassportScanProfile.fullVerification` mirrors the current Notary Journal group list but does not include DG11 or DG7. That means `placeOfBirth`, residence address, phone number, DG11 personal number, and signature/mark images remain absent unless a custom profile opts in. This may be correct for privacy, but Notary Journal should explicitly decide whether those fields are needed.
- `NFCPassportModel` is now an internal working model rather than the public app-facing scan result. It still retains sensitive fields and raw handles internally while a scan is being projected, so ordinary integrations should continue to use `readPassportIdentity(...) -> PassportChipReadResult` and call-site documentation should not steer apps back to the raw model.
- Chip Authentication retry state appears incomplete: `readDataGroups` creates a local `ChipAuthenticationHandler`, but does not assign it to `self.caHandler`. Later retry logic checks `self.caHandler != nil` before falling back from chip-authenticated reads, so that recovery path may never execute after successful CA. This needs an NFC seam or device validation.
- Active Authentication is only attempted when DG15 is read. Policies such as `.activeAuthenticationWhenSupported` and `.fullVerificationWhenSupported` can only know support if DG15 was requested and parsed; app profiles that omit DG15 should treat active-auth status as not checked, not unsupported.
- On-device coverage remains the main release blocker. The private interoperability matrix should cover BAC-only, PACE-GM, PACE-IM, PACE-CAM, CA-supported, AA RSA, AA ECDSA, very large DG2, sparse DG11/DG12, multiple DG7 images, and connection-loss/chunk fallback cases without recording real passport values.

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

- Real-device interoperability remains required before tagging, especially `.fullVerification` with newly included DG7/DG11, PACE-GM, PACE-IM, PACE-CAM, Chip Authentication fallback, RSA/ECDSA Active Authentication, very large DG2, sparse DG11/DG12, and connection-loss/chunk fallback behavior.
- `NFCPassportModel` remains the internal working container for raw data groups, certificates, and Active Authentication material. The public integration path should stay on `PassportChipReadResult`; future cleanup can continue shrinking internal raw retention windows without reintroducing raw public APIs.
- Active Authentication support is still only knowable when DG15 is read. Profiles that omit DG15 should continue to present active authentication as not checked rather than unsupported.

### 2026-06-20 Implementation Gap Cleanup Pass

Completed:

- Redacted `ASN1Item.debugDescription` values so parsed ASN.1 nodes cannot casually dump SOD, certificate, security-info, or OCTET STRING hex values through debug printing.
- Removed public mutable access to BAC key-material fields (`ksenc`, `ksmac`, and `kifd`) and made direct BAC session-key derivation internal to the package. App integrations should use `PassportReader`/`PassportChipReading`, not low-level BAC/session-key flows.
- Changed the privacy-safe `.unexpectedReadFailure` text to `read failed` so logs and diagnostics avoid misleading "expected/unexpected" wording.
- Cleaned up default NFC sheet copy for grammar, punctuation, and clearer multi-tag guidance.
- Moved `verifyingDataGroups` progress emission before synchronous passport verification, so progress events reflect the actual work order.
- Updated README and Notary migration notes to warn against backend transfer of active-authentication data or raw chip data without explicit privacy-reviewed controls.
- Added a regression test that ASN.1 debug descriptions redact long hex values.

Verification:

- iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 90 tests, 0 failures.

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted risky-pattern search found no active production raw logging, print diagnostics, direct `Logger`, `os_log`, runtime traps, clipboard, persistence, network, or accidental raw-export usage. Remaining hits are expected internal APDU/key code paths, typed redacted events, documentation, and negative-test fixtures.

### 2026-06-20 Full Bug Check Loop

Completed:

- Tightened secure-messaging response parsing so `unprotect(rapdu:)` rejects trailing bytes after the checksum object instead of accepting malformed protected responses.
- Corrected legacy secure-messaging tests to model CoreNFC responses accurately, with status words provided separately from `ResponseAPDU.data`.
- Made DG1 MRZ parsing require exact TD1/TD2/TD3 lengths, preventing non-standard trailing MRZ bytes from being silently accepted.
- Hardened DG14 `SecurityInfo` public-key extraction against negative or out-of-bounds ASN.1 dump offsets before slicing raw body bytes.
- Hardened OpenSSL signature/CMAC wrappers by validating digest/context allocation and using scoped Swift unsafe-buffer access for C calls.
- Added sanitized `rawDataImportErrors` for legacy `NFCPassportModel(from:)` raw-dump import so malformed Base64 or data groups are not silently ignored.
- Removed raw SOD/computed hash values from passive-authentication error payloads; mismatch errors now carry summary text only.
- Fixed APDU status-word success handling so only exact `90 00` is accepted. Partial matches such as `90 01` and `91 00` are now failures.
- Redacted fallback status-word diagnostic text and kept retry behavior on typed status-word fields instead of string diagnostics.
- Removed stale temporary logging/comment leftovers found during the audit.
- Updated README and Notary migration notes for the sanitized raw-dump import behavior.

Verification:

- Focused tests passed for secure-messaging trailing bytes, exact DG1 length rejection, malformed SecurityInfo offsets, OpenSSL signature/CMAC paths, raw-dump import errors, passive-authentication error payloads, and status-word classification.
- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 97 tests, 0 failures.

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Repeated risky-pattern loops over logging, runtime traps, raw hash/status diagnostics, unsafe C boundaries, raw export/import APIs, and stale implementation markers found no new actionable production issues after the fixes above. Remaining hits are expected typed internals, test fixtures, or documentation references.

### 2026-06-20 Remaining Plan Implementation Pass

Completed:

- Added `PassportReaderScanStage` and stage-aware `PassportReaderFailure` metadata so host apps can make retry decisions using safe scan phases such as waiting, connecting, PACE, BAC, reading a named data group, chip authentication, active authentication, passive authentication, and security-policy validation.
- Added `PassportReaderPACEPolicy` to keep compatible BAC fallback by default, require PACE when advertised, or require an explicit CAN/PIN/PUK credential for workflows that should fail closed. Strict PACE policies are checked before opening an NFC scan when possible and again before attempting PACE.
- Added `PassportDataGroupReadReport` and model/result/diagnostics propagation so support flows can see whether data groups were requested, advertised, read, skipped, blocked, unsupported, or failed without exposing raw group contents.
- Added `PassportInteroperabilityRecord` for private real-device compatibility tracking with non-identifying country/feature-class outcomes and validation against MRZ-like text or long hex samples.
- Added parser hardening tests for oversized DG7 image items and deterministic malformed ASN.1/data-group fuzz inputs, keeping all fixtures synthetic.
- Updated `PassportChipReading` and `PassportReaderFixture` so app tests can exercise scan options, security policy, and PACE policy through the injectable reader abstraction.
- Added `scripts/release_check.sh` and updated the iOS package workflow to use it for build, test-build, privacy scan, whitespace, and risky-diagnostics review.
- Updated README, Notary migration notes, and the threat model for PACE policy, stage-aware failure metadata, data-group read reports, interoperability records, and the release-check workflow.

Verification during this pass:

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 107 tests, 0 failures.

- Consolidated release check passed:

  ```sh
  scripts/release_check.sh
  ```

  This reran the iOS package build, iOS build-for-testing, `scripts/privacy_scan.sh`, `git diff --check`, and the targeted risky-diagnostics search. Remaining search hits were reviewed as expected documentation, test fixtures, typed APDU/key internals, or redacted event logging.

Remaining external or versioned follow-up:

- Real-device interoperability remains required before tagging. The private matrix should include BAC-only, PACE-GM, PACE-IM, PACE-CAM, CA-supported, AA RSA, AA ECDSA, very large DG2, sparse DG11/DG12, multiple DG7 images, strict PACE policy, and connection-loss/chunk fallback behavior without recording real passport values.
- Screenshot/background redaction and any Notary Journal UI retention controls must be implemented and verified in the app repo because this package does not own host-app screens, snapshots, analytics, crash-report configuration, clipboard policy, or persistence.
- Certificate revocation checking remains explicitly not performed. Do not imply revocation status until the fork has a defined CRL/PKD data source, cache policy, offline behavior, test vectors, and real-device/revoked-certificate validation.
- `NFCPassportModel` still retains raw compatibility properties internally. A future major version can further shrink or isolate those internals, but ordinary app integrations should remain on the privacy-first result types.

### 2026-06-20 Repository Structure Pass

Completed:

- Reorganized the single `NFCPassportReader` Swift target into responsibility-focused source folders without changing module names or public API declarations:
  - `API` for app-facing protocols, result types, scan options, policies, and trust labels.
  - `Reader` for `PassportReader` orchestration and the compatibility `NFCPassportModel`.
  - `Diagnostics` for privacy-safe logging, progress, display messages, failure mapping, scan stages, support summaries, read reports, and interoperability records.
  - `NFC` for low-level tag/APDU transport helpers.
  - `Authentication` for BAC, PACE, secure messaging, session keys, and chip authentication.
  - `Crypto` for OpenSSL-facing Swift helpers, X.509, and encryption wrappers.
  - `Verification` for passive-authentication hashes and verification detail/result types.
  - `Parsing` for TLV/ASN.1/string/byte parsing utilities and the data-group parser dispatcher.
  - `Privacy` for package-owned host-app privacy copy.
  - `Unsafe` for explicit raw export compatibility code guarded by policy.
- Kept `DataGroups`, `Models`, `Resources`, and `OpenSSLCompat` as dedicated existing boundaries.
- Mirrored tests into `Core`, `Diagnostics`, and `Parsing` subfolders so future privacy, parser, and regression work has a predictable home.
- Added `REPOSITORY_STRUCTURE.md` with the full folder map, where-to-start guidance, test layout, fixture cautions, and structural-change verification commands.
- Updated `readme.md` with a concise repository-structure overview for app integrators and maintainers.
- Updated `scripts/privacy_scan.sh` to account for the new `Reader/NFCPassportModel.swift` location when checking accidental legacy raw export usage.

Verification:

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 107 tests, 0 failures.

- Consolidated release check passed:

  ```sh
  scripts/release_check.sh
  ```

  This reran the iOS package build, iOS build-for-testing, `scripts/privacy_scan.sh`, `git diff --check`, and the targeted risky-diagnostics search. Remaining search hits were reviewed as expected documentation, negative-test fixtures, typed APDU/key internals, or redacted event logging.

- A direct stale-path search for old root-level source/test locations returned no hits.

Remaining follow-up:

- No public API migration is intended from this pass. If future source locations are documented in downstream app notes or scripts, update those references to the new folder structure.

### 2026-06-20 Future-Ready API Break Pass

Context:

- Product direction changed: no app currently depends on this fork, so preserving upstream/source compatibility is no longer a goal.
- Earlier compatibility decisions in this plan are superseded by this pass where they conflict with a privacy-first public API.

Completed:

- Made `NFCPassportModel` an internal working model rather than an app-facing public result type.
- Made the raw `PassportReader.readPassport(...) -> NFCPassportModel` overloads internal. Public app scans should use `readPassportIdentity(...)` and receive `PassportChipReadResult`.
- Removed public raw dump import/export surfaces: `NFCPassportModel(from:)`, `dumpPassportData(...)`, `UnsafePassportRawDataExporter`, `PassportReaderSecurityPolicy.allowsUnsafeRawDataExport`, and raw import error plumbing.
- Updated `PassportChipReading` and `PassportReaderFixture` to return `PassportChipReadResult`, so simulator/UI tests do not require a raw passport model.
- Added a safe `readPassportIdentity(...)` overload for explicit CAN/PIN/PUK PACE credentials.
- Made low-level tracking/test hooks internal: `PassportReaderTrackingDelegate`, `trackingDelegate`, `overrideNFCDataAmountToRead(amount:)`, and the ad hoc `readPassportIdentity(tags:)` overload are no longer public API. Apps should use typed progress events, `PassportScanProfile.custom(...)`, or `PassportScanOptions`.
- Updated `scripts/privacy_scan.sh` to fail if removed raw import/export APIs reappear in production sources.
- Updated README, Notary migration notes, threat model, and repository structure docs to describe the safe-result boundary and the internal-only raw model.

Verification during this pass:

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 106 tests, 0 failures.

- Post-cleanup verification reran successfully after making the low-level tracking/test hooks internal:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  scripts/privacy_scan.sh
  git diff --check && git diff --cached --check
  ```

  Result: iOS build passed, simulator suite passed 106 tests with 0 failures, privacy scan passed, and diff whitespace checks passed.

- A broad risky-pattern search found no active production raw logging, removed raw import/export APIs, or direct print/Logger/os_log sinks. Remaining hits were reviewed as documentation, negative-test fixtures, internal APDU/key type names, or scanner patterns.

- `scripts/release_check.sh` was attempted after the successful direct build/test run, but the local Xcode/CoreSimulator services failed to initialize and xcodebuild reported package discovery errors despite `Package.swift` being present. Treat this as an environment issue for this handoff; rerun the release wrapper before tagging if CoreSimulator is restarted.

### 2026-06-20 Parser Standards Coverage Pass

Completed:

- Expanded LDS optional-text decoding for DG11 and DG12. `LDSStringDecoder` is now BOM-aware for UTF-8 and UTF-16, uses UTF-16 endianness heuristics for null-padded text, and falls back through common Latin encodings before replacement UTF-8. This improves multilingual issuer-field handling without exposing raw text bytes in diagnostics.
- Expanded DG2 face-image handling to preserve multiple biometric information templates when a chip includes more than one template in DG2, and multiple facial records embedded inside a single ISO/IEC 19794-5 face-image payload. The existing `imageData` compatibility property remains the first retained image, while `imageDataItems` retains all parsed images.
- Relaxed DG2 JPEG validation from only accepting JFIF APP0 headers to accepting standard JPEG marker starts, while keeping JPEG 2000 support, byte limits, dimension limits, feature-point bounds, and malformed-payload rejection.
- Updated README support notes to state the package's LDS1 eMRTD scope, DG2 multiple-image behavior, broader DG11/DG12 decoding, and explicit non-support for optional LDS2 applications.

Tests added:

- DG2 JPEG payload with a non-JFIF marker is accepted.
- DG2 multiple biometric templates preserve all image payloads while keeping first-image compatibility.
- DG2 multiple facial records inside one biometric template preserve all image payloads while keeping first-image compatibility.
- DG11 UTF-16 big-endian text with BOM parses correctly.
- DG12 Latin-1 issuer text parses correctly.

Verification:

- Focused iOS simulator core/parsing suites passed after the Active Authentication RIPEMD160 fix:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 74 tests, 0 failures.

- Focused iOS simulator parsing suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 42 tests, 0 failures.

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 111 tests, 0 failures.

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Consolidated release check passed:

  ```sh
  scripts/release_check.sh
  ```

  This reran the iOS package build, iOS build-for-testing, `scripts/privacy_scan.sh`, `git diff --check`, and the targeted risky-diagnostics search.

- Targeted scan of changed files found no new active runtime logging, raw export APIs, raw APDU/key diagnostics, or sensitive byte dumps. Remaining hits are expected documentation, synthetic parser fixtures, negative-test assertions, and internal type names.

Remaining follow-up:

- PACE Integrated Mapping (IM) now has standards-vector implementation coverage; real-chip validation still remains before the fork can claim complete PACE coverage for every standards-compliant passport.
- DG2 multi-image parsing now has synthetic coverage for multiple biometric templates and multiple facial records in one template. Real-chip fixture validation is still needed before claiming exhaustive DG2 biometric-record interoperability.
- LDS2 applications remain out of scope for this package unless product requirements expand beyond LDS1 eMRTD passport identity reads.
- Real-device interoperability remains required before tagging.

### 2026-06-20 PACE CAM Selection Pass

Completed:

- Allowed ECDH PACE Chip Authentication Mapping (CAM) OIDs to be selected for reader PACE attempts when standardized domain parameters are available.
- Routed CAM mapping through the same Generic Mapping exchange, matching the ICAO description that CAM extends Generic Mapping, and required the final CAM data object (`0x8A`) to be present before accepting the PACE exchange.
- Added internal CAM proof validation for the DG14 path. The final CAM data object is decrypted with the PACE encryption key, unpadded, and checked by verifying that `CAIC * PKIC` equals the chip's PACE mapping public key for one of the DG14 `ChipAuthenticationPublicKeyInfo` keys.
- Treat a successful DG14 CAM proof as chip-authentication success and skip redundant separate Chip Authentication in that case. If the DG14 proof is absent or fails, the existing separate Chip Authentication flow can still run when supported.
- Kept CAM proof material internal. The transient CAM verification result is cleared after DG14 proof evaluation and is also cleared by model sensitive-data cleanup.
- Added internal EF.CardSecurity reading and CMS encapsulated SecurityInfos parsing for master-file file `011D`. This is intentionally non-trusting until EF.CardSecurity signature validation is implemented.
- Updated README support notes to distinguish implemented DG14-based CAM proof validation and EF.CardSecurity parsing from the remaining trust-based EF.CardSecurity key-selection gap.

Tests added:

- ECDH-CAM PACEInfo is considered readable for PACE selection.
- Synthetic ECDH-CAM proof verification succeeds against the matching chip-authentication public key and fails against a different key.
- Synthetic EF.CardSecurity CMS encapsulated SecurityInfos content parses into PACE security info without using real passport data.

Verification:

- Focused iOS simulator diagnostics suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 47 tests, 0 failures.

- Focused iOS simulator parsing suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 41 tests, 0 failures.

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 114 tests, 0 failures.

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh`, `git diff --check && git diff --cached --check`, and `scripts/release_check.sh` passed.
- Targeted scan of changed files found no new active runtime logging, raw export APIs, raw APDU/key diagnostics, or sensitive byte dumps. Remaining hits are expected documentation, synthetic parser fixtures, negative-test assertions, and internal type names.

Remaining follow-up:

- PACE Integrated Mapping (IM) now has standards-vector implementation coverage in the later IM pass; real-chip validation still remains.
- EF.CardSecurity signature validation and trust-based CAM key selection now have implementation coverage, but still need real-document validation with a trusted master list before release claims are broadened.
- Real-device interoperability remains required before tagging.

### 2026-06-20 EF.CardSecurity CAM Trust Pass

Completed:

- Added CMS signature verification for EF.CardSecurity using the same privacy-safe encapsulated-content extraction path as SOD verification, with optional CSCA/master-list trust-store validation.
- Kept parse-only EF.CardSecurity content non-trusting. Parsed SecurityInfos can be inspected internally, but they satisfy CAM only when the EF.CardSecurity signer was verified against the configured trust store.
- Allowed a trusted EF.CardSecurity chip-authentication public key to validate PACE-CAM immediately after PACE succeeds. If trusted EF.CardSecurity validation is unavailable or fails, the existing DG14 CAM proof path and separate Chip Authentication fallback remain in place.
- Cleared transient EF.CardSecurity CMS bytes after signature verification attempts and kept CAM proof material internal.
- Updated README support notes so CAM coverage distinguishes trusted EF.CardSecurity CAM, DG14 CAM fallback, separate Chip Authentication fallback, and the then-remaining PACE-IM path. PACE-IM implementation coverage was added in the later 2026-06-20 IM pass.

Tests added:

- Synthetic EF.CardSecurity content still parses without real passport data.
- Synthetic unsigned EF.CardSecurity content fails CMS verification and does not become trusted.

Verification:

- Focused iOS simulator parsing suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 43 tests, 0 failures.

- Focused iOS simulator diagnostics suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 47 tests, 0 failures.

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 115 tests, 0 failures.

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh`, `git diff --check && git diff --cached --check`, and `scripts/release_check.sh` passed.
- Targeted scan of changed files found no new active runtime logging, raw export APIs, raw APDU/key diagnostics, or sensitive byte dumps. Remaining hits are expected documentation, synthetic parser fixtures, negative-test assertions, internal type names, and typed redacted event logging.

Remaining follow-up:

- PACE Integrated Mapping (IM) now has standards-vector implementation coverage in the later IM pass; real-chip validation still remains.
- EF.CardSecurity trust behavior still needs real-document validation with an actual master list.
- Real-device interoperability remains required before tagging.

### 2026-06-20 PACE Integrated Mapping Pass

Completed:

- Implemented PACE Integrated Mapping (IM) step 2 for standardized DH and ECDH domain parameters. The reader now sends the terminal IM nonce in mapping data object `0x81`, requires the chip's `0x82` response to be empty, derives the IM field value from the decrypted passport nonce and terminal nonce, and creates mapped domain parameters before key agreement.
- Added the IM pseudorandom field mapping for AES and 3DES PACE cipher suites using the ICAO CBC-based construction with zero IV and the standardized `c0`/`c1` constants.
- Added OpenSSLCompat helpers for DH IM parameter mapping (`gHat = Rp(s,t)^((p-1)/q) mod p`) and ECDH IM parameter mapping using the ICAO Appendix B affine point-encoding algorithm.
- Updated PACE option selection so implemented IM options with standardized domain parameters are eligible for reading, alongside GM and ECDH-CAM.
- Kept IM inputs and mapped parameters internal. No nonce, key, APDU, mapped-field, or generator bytes are logged or surfaced through public diagnostics.
- Updated README support notes so IM is no longer described as unsupported, while retaining the real-device validation requirement before broad release claims.

Tests added:

- ICAO Appendix H ECDH IM pseudorandom field mapping vector.
- ICAO Appendix H ECDH IM mapped generator vector.
- ICAO Appendix H DH IM mapped generator vector.
- PACE option selection now preserves an implemented IM option before a later GM option instead of treating IM as unsupported.

Verification:

- Focused iOS simulator diagnostics suite passed after the IM selection update:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 50 tests, 0 failures.

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 118 tests, 0 failures.

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh`, `git diff --check && git diff --cached --check`, and `scripts/release_check.sh` passed.
- Targeted scan of changed files found no new active runtime logging, raw export APIs, raw APDU/key diagnostics, or sensitive byte dumps. Remaining hits are expected README/plan privacy wording, synthetic ICAO/test vectors, negative-test fixtures, typed APDU/key internals, and redacted event logging.

Remaining follow-up:

- Real-device interoperability remains required before tagging, especially passports that advertise PACE-IM only, multiple PACE options, ECDH-CAM with EF.CardSecurity trust, and chips using 3DES IM suites.
- The ECDH IM implementation matches ICAO vectors, but real-chip timing/interoperability behavior still needs validation on device before claiming exhaustive PACE coverage.

### 2026-06-20 PACE IM Edge-Coverage Pass

Completed:

- Added direct test coverage that BER-TLV data-object helpers preserve zero-length values. This covers the PACE-IM `0x82 0x00` chip mapping response shape required by the standard.
- Added direct negative coverage that PACE Integrated Mapping field derivation rejects malformed passport or terminal nonce lengths before calculating mapped parameters.
- Cleaned stale plan wording that still described PACE-IM as an unsupported boundary after the later IM implementation pass.

Verification:

- Focused iOS simulator core utility suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 26 tests, 0 failures.

- Focused iOS simulator diagnostics suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 51 tests, 0 failures.

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 120 tests, 0 failures.

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh`, `git diff --check && git diff --cached --check`, and `scripts/release_check.sh` passed.
- Release-check risky-pattern hits were reviewed as expected documentation, negative-test fixtures, typed APDU/key internals, or redacted event logging.

Remaining follow-up:

- Real-device interoperability remains required before tagging, especially PACE-IM-only chips, chips using 3DES IM suites, and multi-option PACE fallback behavior.

### 2026-06-20 Revocation Metadata Clarity Pass

Completed:

- Added `PassportCertificateRevocationCheck`, `PassportCertificateRevocationStatus`, and `PassportCertificateRevocationReason` as privacy-safe typed metadata on `PassportCertificateTrustMetadata`.
- Kept the current behavior conservative: revocation is reported as not checked with reason `.notImplemented` after verification attempts, and not checked with reason `.notRequested` before verification runs.
- Updated README passive-authentication guidance so signer trust and revocation status are separate claims, and callers are told not to infer revocation from master-list trust.
- Removed the unused legacy `hasCertBeenRevoked` helper because it inferred revocation from successful certificate-chain extraction against a caller-supplied file, could mutate signer verification state, and was explicitly untested. Revocation remains unsupported until a real CRL/PKD workflow is designed and verified.
- Removed the unused legacy `NotImplementedDG` class. All LDS1 data-group tags known to the parser now route to concrete parsers or opaque typed data-group classes with the correct `DataGroupId`, so maintenance and diagnostics no longer carry a stale "not implemented" parser surface for supported LDS1 file IDs.
- Corrected privacy-safe PACE protocol display names for DH-IM AES-256 and ECDH-IM 3DES so support diagnostics use standard OID names rather than typoed labels.
- Implemented DG12 `A0` other-person-details parsing. The parser now preserves plain text and exact nested TLV text values, including multilingual content, while falling back to direct text decoding if the payload is not a clean TLV sequence.
- Made DG14 Chip Authentication public-key pointer ownership explicit. Public keys parsed from SecurityInfo now have a clear owner and are freed with their wrapper, while borrowed OpenSSL keys used by CAM tests can opt out to avoid double-freeing.
- Added metadata coverage tests for every supported PACE and Chip Authentication OID so missing mapping, agreement, cipher, digest/key-length, or display-name table entries fail before a passport scan.
- Added a SecurityInfo regression for multi-byte optional identifiers, covering larger Chip Authentication key IDs and PACE parameter IDs encoded by issuers as multi-byte ASN.1 INTEGER values.
- Replaced SecurityInfo parsing for EF.CardAccess, DG14, and EF.CardSecurity with direct DER parsing through the structured ASN.1 node parser instead of OpenSSL ASN.1 dump text. This keeps parsing independent of dump formatting, preserves PACE/Chip Authentication/Active Authentication/unknown records, and rejects invalid SecurityInfos roots rather than silently treating them as empty.
- Preserved each structured ASN.1 node's original encoded bytes and use those bytes when parsing SecurityInfo public keys, avoiding compatibility loss from re-encoding valid long-form lengths or multi-byte tags before handing data to OpenSSL.
- Replaced SOD CMS field extraction with direct structured ASN.1 parsing instead of OpenSSL ASN.1 dump text. Encapsulated content, digest algorithm, signed attributes, messageDigest, signature bytes, and signature algorithm are now extracted from `SimpleASN1Node`, with signed attributes preserving original encoded bytes except for the required CMS `[0]` to `SET` tag substitution used during verification.
- Removed the legacy OpenSSL ASN.1 dump parser and raw dump helper entirely. `SecurityInfo` no longer has an `ASN1Item` factory, structured ASN.1 debug descriptions redact values by default, and recognized Chip Authentication public-key SecurityInfos now fail closed if OpenSSL cannot parse the key instead of falling through to an unknown-security-info object.
- Removed the remaining SOD hash text-dump parser. Passive Authentication now parses LDS Security Object hashes only from structured DER, so malformed data-group-number coverage no longer depends on OpenSSL dump-text formatting.
- Tightened Active Authentication verification detail semantics. A fresh model now reports Active Authentication as not requested, a COM without DG15 reports it as not supported, and an advertised DG15 skipped by profile/policy reports it as skipped; enforcement behavior remains unchanged.
- Fixed Active Authentication ECDSA digest selection for `ecdsa-plain-RIPEMD160`. The signature algorithm OID was already parsed, but verification previously fell through to the default SHA-256 digest instead of asking OpenSSL for RIPEMD160.
- Corrected a stale Active Authentication RSA comment that said ISO9796-2 two-byte trailer hash selection was unimplemented, even though SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 trailer bytes are handled.
- Added parser coverage for TD1 and TD2 DG1 MRZ layouts in addition to the existing TD3-length passport MRZ test, using synthetic data only.
- Tightened Chip Authentication verification detail and strict policy semantics. A fresh model now reports Chip Authentication as not requested, DG14-not-advertised reports not supported, and advertised-but-skipped DG14 reports skipped. `chipAuthenticationWhenSupported`, `activeAuthenticationWhenSupported`, and `fullVerificationWhenSupported` now fail when DG14/DG15 was advertised but skipped by profile or policy instead of treating skipped advertised mechanisms as unsupported.

Tests added:

- Default identity results report revocation as not checked and not requested.
- Verification attempts without a revocation workflow report revocation as not checked and not implemented, using privacy-safe explanation text.
- PACE protocol OID string tests cover the corrected IM labels.
- DG12 other-person-details tests cover both plain text and nested multilingual TLV payloads.
- Supported PACE and Chip Authentication OID metadata tests cover all currently supported standard combinations.
- SecurityInfo optional-identifier tests cover multi-byte key ID and parameter ID parsing.
- DG1 parser tests now cover TD1, TD2, and TD3-length MRZ layouts with synthetic MRZ strings.
- SecurityInfos parser tests cover mixed DER records for PACE, Chip Authentication, Active Authentication, and unknown security info without relying on OpenSSL dump text.
- Structured ASN.1 node tests cover preservation of original encoded bytes, including long-form length headers.
- SOD CMS parser tests cover encapsulated content, digest algorithm, signed attributes, messageDigest, signature bytes, signature algorithm, and optional CMS certificate/CRL field positioning without relying on OpenSSL dump text.
- ASN.1 debug-description tests now cover the structured parser's redacted output directly.
- SecurityInfo tests now cover multi-byte optional identifiers, unknown OID preservation, and malformed recognized public-key records through DER parser paths without using dump-parser fixtures.
- Structured SOD hash tests now cover valid hash extraction plus invalid and zero data-group numbers without using text-dump fixtures.
- Active Authentication detail tests cover default not-requested, COM-not-advertised not-supported, and advertised-but-skipped DG15 cases.
- Active Authentication signature-algorithm metadata tests cover all supported ECDSA plain OIDs, including RIPEMD160, and the OpenSSL signature digest selector now has focused coverage for those names.
- Chip Authentication detail and strict-policy tests cover advertised-but-skipped DG14/DG15 failures plus non-advertised mechanisms satisfying the "when supported" policies.

Verification:

- Focused iOS simulator parsing suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 49 tests, 0 failures.

- Focused iOS simulator diagnostics suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 61 tests, 0 failures.

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 137 tests, 0 failures.

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh`, `git diff --check && git diff --cached --check`, and `scripts/release_check.sh` passed.
- Release-check risky-pattern hits were reviewed as expected documentation, negative-test fixtures, typed APDU/key internals, or redacted event logging.
- Targeted risky-pattern search found no new active raw logging sink. Remaining hits were reviewed as expected README/plan privacy wording, negative-test fixtures, synthetic parser data, internal APDU/key type names, OpenSSL API names, and redacted event logging.
- Legacy-parser symbol scan found no `ASN1Item`, `SimpleASN1DumpParser`, `ASN1Parse(`, or `ASN1_parse_dump` references left in `Sources` or `Tests`.
- GitHub Actions run `27880003695` for commit `718c51c` failed in `xcodebuild ... build-for-testing` under Xcode 16.4/iOS 18.5 because the Swift compiler could not type-check the large chained byte-array expression in `iso19794FaceRecord(...)` in reasonable time. The production package build had already succeeded before the test build failed. Rewrote that synthetic test fixture helper to append into a reserved `[UInt8]` buffer step by step; behavior and bytes are unchanged, but older Swift compilers avoid the type-checking timeout.
- Local verification after the CI compatibility fix passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  This local machine only has `/Applications/Xcode.app`, not GitHub's `/Applications/Xcode_16.4.app`; rerun Actions after pushing to verify the exact runner compiler.

Remaining follow-up:

- A real revocation workflow still requires a defined CRL/PKD data source, cache policy, offline behavior, test vectors, and real-device/revoked-certificate validation before `revocationCheckPerformed` can ever be true.

### 2026-06-20 Legacy Low-Level Surface Narrowing

Completed:

- Reviewed the remaining public low-level protocol, parser, certificate, byte-conversion, AES/DES, and OpenSSL helper symbols after the public scan API was moved to `PassportChipReadResult`.
- Confirmed the app-facing read path still avoids returning raw data groups, APDUs, certificates, secure-messaging keys, and Active Authentication challenge/signature bytes through `PassportChipReadResult`; chip photo bytes are exposed only through the explicit sensitive `faceImageData` field when the effective photo policy is `.read`.
- Made low-level NFC/session protocol types module-internal: `TagReader`, `ResponseAPDU`, `BACHandler`, `PACEHandler`, `SecureMessaging`, and `SecureMessagingSupportedAlgorithms`.
- Made low-level byte, hash, MAC, padding, ASN.1-length, OID, AES/DES, OpenSSL, certificate-wrapper, raw data-group parser, SecurityInfo, FaceImageInfo, and internal hash-detail helpers module-internal.
- Kept `DataGroupId` public because it is part of safe scan profiles, diagnostics, and read reports.
- Kept safe app-facing types public: `PassportReader`, `PassportChipReadResult`, `PassportIdentityResult`, scan options/profiles/policies, privacy-safe diagnostics, verification summaries, trust metadata, revocation metadata, and non-identifying interoperability records.
- Made `NFCPassportReaderError` default stringification privacy-safe by conforming to `CustomStringConvertible` and returning `safeDescription`, so accidental `String(describing:)` logging does not include low-level associated values.
- Made `OpenSSLError` and `PassiveAuthenticationError` module-internal. Their localized descriptions remain privacy-safe for internal wrapping and tests.
- Updated README wording to clarify that low-level NFC, BAC, PACE, secure-messaging, crypto, certificate-wrapper, and raw data-group parser types are not public app scan APIs.
- Updated README logging guidance to state that reader error `localizedDescription` and `String(describing:)` output are privacy-safe summaries.

Tests added:

- Reader error default string descriptions reject sensitive status-word, APDU, PACE token, and key-material fragments.

Verification:

- Focused iOS simulator diagnostics suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 62 tests, 0 failures.

- Required iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 138 tests, 0 failures.

- Whitespace checks passed:

  ```sh
  git diff --check && git diff --cached --check
  ```

- `scripts/privacy_scan.sh` passed.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  This reran the required iOS package build, iOS build-for-testing, privacy scan, whitespace check, and risky-diagnostics search. Risky-pattern hits were reviewed as expected documentation, negative-test fixtures, typed APDU/key internals, OpenSSL API names, or redacted event logging.

Remaining follow-up:

- This is a deliberate public API cleanup for the privacy fork. Downstream integrations that were using original-package internals should migrate to `PassportReader.readPassportIdentity(...)`, `PassportScanOptions`, `PassportChipReadResult`, and `PassportChipReading`.
- Do not add new app-facing raw cryptographic, NFC, certificate, APDU, SecurityInfo, or raw data-group parser APIs. Ordinary integrations should stay on the privacy-first result surface.

### 2026-06-20 Interoperability Record Privacy Hardening

Completed:

- Tightened `PassportInteroperabilityRecord.containsOnlyNonIdentifyingFields` so private real-device matrix notes reject more sensitive shapes than the previous long-MRZ/long-hex checks.
- Added rejection for common sensitive labels such as MRZ, passport/document number, date of birth, expiration, names, photo/image, APDU/RAPDU, BAC/PACE/session keys, Kseed/KSenc/KSmac, RND.IFD/RND.ICC, certificate serials, fingerprints, and thumbprints.
- Added rejection for separated byte/hex samples such as APDU AIDs, key fragments, certificate fingerprints, or colon/dash/space-delimited hex.
- Updated README compatibility-tracking guidance to make clear that the validation helper is a safeguard, not permission to store scan artifacts.

Tests added:

- Interoperability records now reject sensitive labels and separated hex samples in notes while preserving the existing synthetic safe-note path.

Verification:

- Focused iOS simulator diagnostics suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 63 tests, 0 failures.
- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 139 tests, 0 failures.
- Required generic iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/privacy_scan.sh` passed.
- `git diff --check && git diff --cached --check` passed.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  This reran the required iOS package build, iOS build-for-testing, privacy scan, whitespace check, and risky-diagnostics search. Risky-pattern hits were reviewed as expected documentation, negative-test fixtures, typed APDU/key internals, OpenSSL API names, or redacted event logging.

Remaining follow-up:

- The private interoperability matrix still needs real-device data gathered without identity details before release claims can be broadened.

### 2026-06-20 External Public API Surface Probe

Completed:

- Added `scripts/api_surface_check.sh`, which creates temporary external SwiftPM consumer packages and builds them for generic iOS through Xcode.
- The safe consumer verifies that an app target can compile against the intended privacy-first public surface, including `PassportReader`, `PassportChipReading`, `PassportScanOptions`, scan profiles, diagnostics, privacy copy, verification summaries, revocation metadata, progress events, and interoperability records.
- The unsafe consumer intentionally tries to use low-level implementation symbols that should not be app-facing: `NFCPassportModel`, `TagReader`, `ResponseAPDU`, `BACHandler`, `PACEHandler`, `SecureMessaging`, `DataGroup`, `SecurityInfo`, and `OpenSSLUtils`. The check now fails the release gate if those symbols become externally available.
- Wired the external API surface probe into `scripts/release_check.sh` after iOS build-for-testing and before privacy scanning.

Verification:

- External API surface check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/api_surface_check.sh
  ```
- Consolidated release check passed with the new external API surface probe included:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  This reran the required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search. Risky-pattern hits were reviewed as expected documentation, negative-test fixtures, typed APDU/key internals, OpenSSL API names, or redacted event logging.

Remaining follow-up:

- Keep this probe aligned with the intended app-facing API if a future release deliberately changes the safe public scan surface.

### 2026-06-20 Face Image Presence Semantics

Completed:

- Tightened `PassportIdentityResult.hasFaceImage` so it checks for an actual parsed DG2 image payload via `DataGroup2.imageDataItems` instead of treating DG2 object presence alone as sufficient.
- Kept behavior aligned with `hasSignatureImage`, which already requires a non-empty DG7 image payload.

Tests added:

- Identity results report no face image when DG2 was not read.
- Identity results report a face image when a synthetic DG2 fixture parses with an image payload.

Verification:

- Focused iOS simulator parsing and diagnostics suites passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 114 selected tests, 0 failures.
- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 141 tests, 0 failures.
- `scripts/privacy_scan.sh` passed.
- `git diff --check && git diff --cached --check` passed.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  This reran the required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search. Risky-pattern hits were reviewed as expected documentation, negative-test fixtures, synthetic parser data, typed APDU/key internals, OpenSSL API names, or redacted event logging.

Remaining follow-up:

- Real-device DG2 interoperability still needs validation across chips with multiple biometric templates and multiple facial records before broadening release claims.

### 2026-06-20 Typed Unsupported-Cipher Error Pass

Completed:

- Replaced remaining unsupported-cipher paths that embedded low-level algorithm/key-length detail strings in `PACEError` or `InvalidDataPassed` with the existing typed `NFCPassportReaderError.UnsupportedCipherAlgorithm`.
- Covered PACE secure-messaging restart, Chip Authentication public-key send/restart paths, Chip Authentication digest inference, and `SecureMessagingSessionKeyGenerator` unsupported algorithm/key-length branches.
- Kept public error descriptions privacy-safe and internal retry behavior typed; no supported cipher behavior changed.

Tests added:

- Session-key generation now verifies unsupported algorithm names and unsupported key lengths throw `UnsupportedCipherAlgorithm` and do not include low-level fragments in `value`, `localizedDescription`, or default stringification.

Verification:

- Focused iOS simulator core suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 28 tests, 0 failures.
- Targeted unsupported-cipher detail scan found no remaining detail-bearing messages in sources or tests; the only remaining hit is the generic safe description.
- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 142 tests, 0 failures.
- `scripts/privacy_scan.sh` passed.
- `git diff --check && git diff --cached --check` passed.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic parser fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.

Remaining follow-up:

- Keep future crypto/PACE/CA error branches on typed error cases rather than detail-bearing strings unless a privacy-reviewed diagnostic mode is deliberately added.

### 2026-06-20 Identity Cache Cleanup Pass

Completed:

- Replaced `NFCPassportModel` lazy cached identity accessors with computed accessors backed by the current parsed data groups, including MRZ-derived fields, DG11 optional personal details, face-image metadata, COM metadata, and data-group presence.
- Tightened the existing `readPassportIdentity(...)` cleanup behavior so the internal working model no longer keeps returning previously projected identity values after `removeSensitiveDataForPrivacy()` clears raw data groups.
- Kept the privacy-first `PassportChipReadResult` projection unchanged: callers still receive normalized identity fields and safe verification metadata, while the package drops the working model's raw backing data after projection.

Tests added:

- Added a synthetic TD3 DG1 regression test proving `PassportIdentityResult` preserves projected identity values, then `NFCPassportModel.removeSensitiveDataForPrivacy()` clears the backing group and subsequent model access returns empty/default values instead of stale document number, name, birth date, or expiry date.

Verification:

- Focused iOS simulator diagnostics suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 65 tests, 0 failures.
- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 143 tests, 0 failures.
- `scripts/privacy_scan.sh` passed.
- `git diff --check && git diff --cached --check` passed.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.

Remaining follow-up:

- Cleanup remains best-effort data minimization, not guaranteed memory zeroization. Real-device interoperability and the private matrix remain required before broad release claims.

### 2026-06-20 Failure Path Cleanup Pass

Completed:

- Added a failure-only cleanup path for `PassportReader` that scrubs the partially populated working `NFCPassportModel`, requested data-group queue, current data-group marker, BAC/PACE/CA handlers, MRZ/PACE credential fields, pending PACE credential, and Active Authentication challenge when a scan fails or is canceled.
- Wired the cleanup into `failActiveScan(...)` before the continuation guard, so timeout, cancellation, NFC invalidation, connection loss, security-policy failure, and other failure paths clear partial chip data even if the continuation has already been consumed by a race.
- Preserved the successful `completeActiveScan(...)` path so compatibility callers still receive the completed model, while `readPassportIdentity(...)` continues to project `PassportChipReadResult` and then clean up the returned working model.

Tests added:

- Added a reader lifecycle regression test that seeds the private working model with a synthetic parsed data group and Active Authentication material, invokes the failure cleanup path, and verifies both the old model instance and replacement reader model no longer expose the partial data.

Verification:

- Focused iOS simulator diagnostics suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 66 tests, 0 failures.
- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 144 tests, 0 failures.
- `scripts/privacy_scan.sh` passed.
- `git diff --check && git diff --cached --check` passed.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.

Remaining follow-up:

- Cleanup remains best-effort data minimization, not guaranteed memory zeroization. On-device scans are still needed to validate failure behavior under real connection loss and chip-removal timing.

### 2026-06-20 Authentication Session Cleanup Pass

Completed:

- Added explicit best-effort cleanup hooks for retained BAC key material and randoms, secure-messaging session keys/counter, PACE transient access-key/mapping fields, and Chip Authentication command/session state.
- Added deinit cleanup for BAC, PACE, Chip Authentication, and Secure Messaging helper objects so releasing a handler also scrubs its own retained byte buffers where Swift allows.
- Updated `PassportReader.completeActiveScan(...)` so successful compatibility reads still return the completed `NFCPassportModel`, but the reader object drops authentication handlers, MRZ/PACE credential fields, requested data-group queue, current data-group marker, optional Active Authentication challenge, and display/progress closure references after completion.
- Updated failure cleanup to reuse the same authentication-state discard path after clearing the partial working model.
- Preserved PACE-CAM behavior by keeping the CAM mapping result available long enough for the reader to copy it into the working model for DG14 validation, while still clearing the handler's transient PACE key and mapping fields.

Tests added:

- Secure Messaging cleanup now verifies session encryption key, MAC key, and send-sequence counter buffers become empty and cannot be reused to protect another command.
- BAC cleanup now verifies derived BAC keys, chip/reader randoms, and terminal key material buffers become empty after cleanup.

Verification:

- Focused iOS simulator core suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 30 tests, 0 failures.
- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 146 tests, 0 failures.
- `scripts/privacy_scan.sh` passed.
- `git diff --check && git diff --cached --check` passed.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.

Remaining follow-up:

- Cleanup remains best-effort data minimization, not guaranteed memory zeroization. Real-device validation is still required for BAC/PACE/CA success, fallback, and connection-loss timing.

### 2026-06-20 Data Group Retention Cleanup Pass

Completed:

- Added an internal `DataGroup.removeSensitiveDataForPrivacy()` scrub hook that clears retained raw data-group body/data buffers and parser offsets.
- Wired `NFCPassportModel.removeSensitiveDataForPrivacy()` to scrub every retained data group before releasing the model dictionary, so externally retained internal data-group references do not keep raw chip payloads alive after cleanup.
- Added subclass cleanup for MRZ fields in DG1, personal text in DG11/DG12, DG2/DG7/DG12 image byte arrays, DG14 parsed security infos, SOD certificate/ASN.1/public-key state, and DG15 OpenSSL public-key pointers.
- Kept the cleanup best-effort and internal; no public API migration is required.

Tests added:

- Added a model privacy cleanup regression that retains references to DG1, DG2, DG7, DG11, and DG12, invokes model cleanup, and verifies raw buffers, images, MRZ fields, and personal text fields are cleared before the model releases its data-group dictionary.

Verification:

- Focused model cleanup regression passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests/testModelPrivacyCleanupScrubsRetainedDataGroupPayloadsBeforeReleasingReferences
  ```

  Result: 1 test, 0 failures.
- Full parsing suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 51 tests, 0 failures.
- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 147 tests, 0 failures.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.

Remaining follow-up:

- Cleanup remains best-effort data minimization, not guaranteed memory zeroization. Real-device scanning is still the only remaining validation for hardware timing, chip variability, and NFC transport behavior.

### 2026-06-20 Notary Adoption Readiness Pass

Completed:

- Refactored the large synthetic DG2 facial-record test expression that caused Swift CI to report `unable to type-check this expression in reasonable time`.
- Fixed `scripts/api_surface_check.sh` to give the local path dependency the explicit package identity `NFCPassportReader` and to reference that identity in `.product(...)`, so the probe is not tied to a checkout directory named `Passport Chip Fork`.
- Added `PassportChipReadResult.faceImageData: PassportChipImageResult?` as an explicit sensitive opt-in result field. It is populated only when the effective `PassportPhotoPolicy` is `.read` and DG2 produced face-image bytes; `.skip` leaves it nil even if a test model contains DG2.
- Added `PassportChipImageResult` with image bytes, format, MIME type, width, and height for app review workflows that intentionally need the chip photo. Documentation now calls out the biometric-data handling requirements.
- Added `PassportIdentityResult.dateOfIssue` projected from DG12 so Notary Journal can continue issue-date autofill without raw `DataGroup12` access.
- Confirmed `PassportVerificationResult` already exposes simple chip/active authentication statuses plus safe detail reasons and `privacySafeExplanation` copy for passed, failed, not supported, and not requested/skipped cases.

Tests added:

- DG2 safe-result projection now verifies `faceImageData` appears for `.read` and is nil for `.skip`.
- DG12 parsing now verifies `PassportIdentityResult.dateOfIssue` carries the normalized issue date.

Verification:

- Focused Notary adoption tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests/testIdentityResultReportsFaceImageOnlyWhenDG2ContainsImagePayload -only-testing:NFCPassportReaderTests/DataGroupParsingTests/testDatagroup12Parsing
  ```

  Result: 2 tests, 0 failures.

- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 147 tests, 0 failures.

- Required iOS package build succeeded:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `scripts/api_surface_check.sh` passed, including the fixed explicit package identity.
- `scripts/privacy_scan.sh` passed.
- `git diff --check` passed.
- Targeted risky-pattern search over changed API/reader/test/docs/script files found no new raw production logging sink. Remaining hits are expected privacy documentation, synthetic test fixtures, typed redacted `eventLogger.log(...)` calls, internal APDU/type names, and the explicit sensitive `faceImageData` API.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.

Remaining follow-up:

- Let GitHub CI run on the pushed branch, then tag a stable fork release such as `notary-2.3.1-privacy.1` only after CI is green and any required real-device Notary validation is complete.

### 2026-06-20 GitHub Actions Ripgrep Dependency Fix

Completed:

- Updated `.github/workflows/ios-package.yml` to install `ripgrep` before running `scripts/release_check.sh`, fixing the GitHub Actions failure where `privacy_scan.sh` could not find `rg`.
- Added a `grep -R -E` fallback to `scripts/privacy_scan.sh` so the privacy gate still runs on minimal environments without `rg`.
- Added the same fallback shape to the risky-pattern report in `scripts/release_check.sh`; the report no longer silently disappears when `rg` is unavailable.

Verification:

- Privacy scan fallback passed with `rg` intentionally absent from `PATH`:

  ```sh
  PATH=/usr/bin:/bin:/usr/sbin:/sbin scripts/privacy_scan.sh
  ```

- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully.

Remaining follow-up:

- Wait for the pushed GitHub Actions run to confirm the hosted macOS runner is green before cutting a stable tag.

### 2026-06-20 Stable Notary Release Tag

Decision:

- Use `notary-2.3.1-privacy.1` as the first stable app-consumption tag for this privacy fork. This avoids pointing Notary Journal at the moving `codex/privacy-safe-logging` branch while still making the fork lineage and privacy purpose explicit.

Pre-tag verification:

- GitHub Actions reported the `iOS Package` workflow for commit `1d59dcb` as `completed | success` after the CI ripgrep dependency fix.

Remaining follow-up:

- Push this plan note, wait for the final branch-head CI run to complete successfully, then create and push `notary-2.3.1-privacy.1` on that exact commit.

### 2026-06-20 OpenSSL Package Upgrade Pass

Decision:

- Upgrade the fork to the newest OpenSSL version currently offered by the existing SwiftPM dependency source, `krzyzanowskim/OpenSSL-Package` `3.6.2000`.
- This package wraps OpenSSL `3.6.2`. OpenSSL `4.0.1` is newer upstream, but no `OpenSSL-Package` 4.x artifact is currently published, so 4.x would require a custom Apple `OpenSSL.xcframework` build and a higher-risk compatibility pass.
- Keep the dependency on the existing Swift package wrapper instead of vendoring a custom OpenSSL binary in this fork.

Implementation status:

- Updated `Package.swift` from `.upToNextMinor(from: "3.3.1000")` to an exact `3.6.2000` OpenSSL-Package pin.
- Resolved `Package.resolved` from `OpenSSL-Package` `3.3.3001` revision `71dbe0b4514cdaad95961470db72e8231f5943a6` to `3.6.2000` revision `2d180b33702e0e67fd58607d1f96d5fad0816d10`.
- Follow-up audit found that the root `Package.resolved` is intentionally ignored by this package repo, so the dependency version is pinned directly in the manifest to keep release resolution reproducible.

Verification:

- Resolved the package graph successfully with `OpenSSL-Package` `3.6.2000`.
- Re-ran dependency resolution from a temporary clean copy with no `.build`, `.swiftpm`, or `Package.resolved`; SwiftPM resolved `OpenSSL-Package` to `3.6.2000`, confirming the manifest-level exact pin is sufficient for fresh checkouts.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully. Risky-pattern hits were reviewed as expected documentation, negative-test fixtures, typed APDU/key internals, OpenSSL API names, or redacted diagnostic events.

- Full iOS simulator unit suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 147 tests, 0 failures.

- Captured release-check and simulator-test logs were scanned for compiler warnings and errors. No source/compiler warnings or errors were found.
- `scripts/privacy_scan.sh` and `git diff --check` passed after the exact-version audit fix.

Remaining follow-up:

- Continue to require real-device passport interoperability validation before broadening release claims.

### 2026-06-21 Swift 6.3 / iOS 26 Migration Pass

Decision:

- Raise this app-only fork to SwiftPM tools 6.3, Swift 6 language mode, and iOS 26.0 minimum deployment. This deliberately drops older consumer/toolchain compatibility because Notary Journal is the only intended consumer and is planned around the current iOS floor.
- Keep the existing privacy-first public API shape, but make the display-message callback explicitly `@Sendable` through `PassportReaderDisplayMessageHandler`.
- Isolate `PassportReader` and scan-session BAC/PACE/Chip Authentication orchestration to the main actor. CoreNFC delegate conformance remains a `@preconcurrency` boundary because the SDK delegate protocol is not fully actor annotated.
- Use narrow, documented legacy-concurrency escapes for CoreNFC transport wrappers and the mutable compatibility `NFCPassportModel` result. Longer term, a future major cleanup can replace the mutable raw model return with value-typed safe results only.

Implementation status:

- Updated `Package.swift` to `// swift-tools-version:6.3` and `platforms: [.iOS("26.0")]`.
- Added `PassportReaderDisplayMessageHandler = @Sendable (NFCViewDisplayMessage) -> String?` and migrated `customDisplayMessage` parameters to that type.
- Made `PassportReader` main-actor isolated and adjusted cancellation to hop back to the main actor.
- Main-actor isolated BAC, PACE, and Chip Authentication handlers, preserving sensitive cleanup with `isolated deinit`.
- Kept `TagReader` and `SecureMessaging` as documented `@unchecked Sendable` wrappers around the CoreNFC/secure-messaging legacy boundary, with single-scan ownership expectations.
- Rewrote the SOD verification fallback selection to explicit branches to avoid a Swift 6.3 compiler diagnostic failure around ternary function references.
- Removed obsolete Linux-style `allTests` arrays and updated focused tests for the new actor isolation.
- Updated `scripts/api_surface_check.sh` so release probes use SwiftPM 6.3, iOS 26.0, and a main-actor safe API probe.
- Updated README and Notary migration notes for the new minimums and `@Sendable` callback requirement.

Verification:

- Required generic iOS package build passed with no source/compiler warnings:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 147 tests, 0 failures. Xcode emitted the known non-source App Intents metadata warning for the XCTest bundle.

- External API surface probe passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/api_surface_check.sh
  ```

- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search all completed successfully. Risky-pattern hits were reviewed as expected documentation, synthetic negative tests, internal APDU/key identifiers, OpenSSL type names, explicit Swift 6 legacy-concurrency boundaries, or redacted diagnostic events.

- Notary Journal app build passed after switching the app project package reference to this local migrated fork:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -project "Notary Journal.xcodeproj" -scheme "Notary Journal" -destination generic/platform=iOS CODE_SIGNING_ALLOWED=NO build
  ```

  Result: build succeeded with no warnings or errors in the saved build log. The app's `Package.resolved` now resolves `OpenSSL-Package` `3.6.2000` through the local fork.

Remaining follow-up:

- Continue to require real-device passport interoperability validation before broadening release claims. Physical-device validation is not required for this Swift 6.3 migration task to be considered complete.

### 2026-06-21 Full Bug-Check And Security Review Pass

Completed:

- Performed a repo-wide source review after the Swift 6.3 / iOS 26 migration, focusing on crash paths, forced operations, concurrency escape hatches, privacy-sensitive diagnostics, and release-gate coverage.
- Hardened the OpenSSL X509 stack helpers so a nil OpenSSL certificate stack returns an empty count or nil value instead of crashing through implicitly unwrapped pointers. This protects the trust-chain path if `X509_STORE_CTX_get1_chain` returns nil after a failed or incomplete OpenSSL verification context.
- Added a focused regression test for nil X509 stack helper inputs.
- Re-reviewed source and test hits for `try!`, forced casts, `fatalError`, assertions, unsafe concurrency annotations, logging sinks, file/pasteboard persistence APIs, APDU/key identifiers, long hex-like values, and passport-sensitive terms.
- Confirmed production diagnostics remain routed through typed redacted events, with no raw MRZ, APDU, BAC/PACE key, session-key, decrypted data-group, certificate-detail, or image-byte logging surfaces introduced by this pass.

Verification:

- Required generic iOS package build passed with no source/compiler warnings:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Focused core test suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 31 tests, 0 failures.

- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 148 tests, 0 failures. Xcode emitted the known non-source App Intents metadata warning for the XCTest bundle.

- External API surface probe passed against a temporary SwiftPM 6.3 / iOS 26 consumer package, including main-actor and protocol-consumer call sites.
- Consolidated release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, and risky-diagnostics search completed successfully. Risky-pattern hits were reviewed as expected documentation, synthetic negative tests, internal APDU/key identifiers, OpenSSL type names, explicit Swift 6 legacy-concurrency boundaries, or redacted diagnostic events.

Remaining follow-up:

- Continue to require real-device passport interoperability validation before tagging or making broad release claims. This pass did not perform physical-device NFC validation.

### 2026-06-21 Maintainability Cleanup Pass

Completed:

- Reviewed the repo for duplicated code, raw parser slicing, branch-heavy mapping code, centralized privacy cleanup points, risky diagnostics, and general code smells after the Swift 6.3 migration.
- Factored DG1 MRZ field extraction through small helpers so TD1, TD2, and TD3-style parsing no longer duplicate raw UTF-8 range conversion logic.
- Replaced DG11 and DG12 tag `if`/`else` chains with switch-based tag mapping.
- Removed duplicated ASN.1 length decoding by routing the array overload through the slice implementation.
- Simplified data-group hash algorithm selection with an explicit switch.
- Centralized `PassportChipReadResult` creation and `NFCPassportModel.removeSensitiveDataForPrivacy()` in one `PassportReader` helper so the public identity-result path has a single scrub point.
- Simplified skipped data-group reporting by removing a duplicate branch that recorded the same `.skippedByProfile` status in both cases.

Verification:

- Focused parsing tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 51 tests, 0 failures.

- Focused core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 31 tests, 0 failures.

- Required generic iOS package build passed with no source/compiler warnings:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 148 tests, 0 failures.

- Risky logging/diagnostic search was reviewed after the cleanup. Hits remained expected synthetic test patterns, OpenSSL API names, and typed redacted event logging.
- `git diff --check` passed.

Remaining follow-up:

- Continue to require real-device passport interoperability validation before tagging or making broad release claims. This cleanup pass did not perform physical-device NFC validation.

### 2026-06-21 Scan/Decode/Flow Performance Pass

Completed:

- Reviewed NFC read flow, progress handling, data-group filtering, decode helpers, certificate/OpenSSL string helpers, and verification summary code for avoidable allocations or repeated work.
- Throttled per-chunk NFC sheet and host progress updates to meaningful 5% increments, while still resetting progress state for each data-group read attempt and rendering stage changes. This reduces UI/main-actor churn during large DG2/DG7 reads without changing APDU read behavior.
- Removed a duplicate 0% data-group progress update before each data-group read.
- Changed data-group read-policy filtering to use a `Set<DataGroupId>` for requested membership checks.
- Changed DG7 image parsing to track total retained image bytes incrementally instead of reducing all parsed image items on every item.
- Removed one extra OpenSSL BIO string allocation by decoding the raw buffer directly instead of mapping through an intermediate `[UInt8]`.
- Avoided repeated cipher-name lowercasing in secure-messaging key derivation.
- Avoided allocating a temporary status array when computing `PassportVerificationResult.overallStatus`.

Verification:

- Focused core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 31 tests, 0 failures.

- Focused diagnostics/privacy tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 66 tests, 0 failures.

- Required generic iOS package build passed with no source/compiler warnings:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full iOS simulator suite passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 148 tests, 0 failures.

- `git diff --check` passed.

Remaining follow-up:

- Continue to require real-device passport interoperability validation before tagging or making broad release claims. This performance pass did not perform physical-device NFC validation or measure device scan timings.

### 2026-06-21 Repository Organization Follow-Up

Completed:

- Reviewed the repository layout against `REPOSITORY_STRUCTURE.md`, the SwiftPM manifest, tracked files, ignored generated state, scripts, tests, and the current CI workflow.
- Kept the existing responsibility-focused source/test folder layout. No source moves were needed.
- Updated `.gitignore` so the tracked maintenance helper files under `scripts/` (`README.md`, `extract.py`, and release/privacy/API scripts) are explicitly unignored while ad hoc script outputs remain ignored.
- Updated `REPOSITORY_STRUCTURE.md` to document `Sources/NFCPassportReader/Unsafe` as an intentionally empty quarantine folder for any future deliberately unsafe compatibility surface that would require plan, docs, tests, and policy gates before use.

Verification:

- `git diff --check` passed.
- `scripts/privacy_scan.sh` passed.
- Required generic iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

Remaining follow-up:

- Continue to keep local SwiftPM/Xcode generated state (`.build`, `.swiftpm`, and root `Package.resolved`) untracked. The OpenSSL dependency remains reproducibly pinned by exact version in `Package.swift`.

### 2026-06-21 SwiftPM Dependency Warning Cleanup

Completed:

- Replaced the deprecated SwiftPM dependency declaration `.package(url:_: .exact(...))` with the current `.package(url:exact:)` form for `OpenSSL-Package` `3.6.2000`.
- Kept the dependency version unchanged and still exactly pinned; this is a manifest syntax cleanup only, not an OpenSSL upgrade or security policy change.
- Updated `AGENTS.md` completion instructions so future AI turns must fix warnings or errors surfaced by build, test, package-resolution, lint, formatting, or verification commands before handoff, or explicitly document an external/toolchain/environment reason when an in-repo fix is not possible.
- Version bump decision: publish these fixes as the next annotated app-consumption tag, `notary-2.3.1-privacy.3`, without moving the existing `notary-2.3.1-privacy.1` or `notary-2.3.1-privacy.2` tags.

Verification:

- `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift package resolve` completed with no manifest deprecation warnings.
- Required generic iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS clean build
  ```

- The clean iOS build log contains no `warning:` diagnostics. Xcode still emits one non-source `note` while processing the remote OpenSSL binary artifact: `The identity of “OpenSSL.xcframework” is not recorded in your project.` The artifact remains checksum-pinned by the upstream `OpenSSL-Package` manifest and version-pinned by this fork's manifest.
- Privacy impact reviewed: no runtime code, logging, diagnostics, data retention, public API, or test fixture behavior changed.

### 2026-06-21 Decryption And Malformed Chip Data Review

Completed:

- Reviewed secure messaging response handling for malformed passport-chip data. Successful protected responses are MAC-verified before encrypted DO87 payloads are decrypted, so an attacker without the negotiated BAC/PACE/CA session keys should not be able to inject protected data for normal data-group parsing.
- Reviewed parser and transport behavior for chip-controlled lengths and malformed responses. Swift bounds checks and CommonCrypto wrappers reduce memory-corruption risk, but malformed chips can still cause scan failure or resource pressure if response sizes are not bounded.
- Hardened `TagReader.selectFileAndRead` so a chip response chunk larger than the advertised ASN.1 file length is rejected instead of being appended into the data group.
- Hardened ISO7816 `GET RESPONSE` chaining with explicit package-side limits: 2 MiB total chained response data and 512 chained segments.
- Added focused unit tests for overlong file chunks, valid remaining-length accounting, and chained-response budget rejection.
- Hardened the structured ASN.1 parser used for SOD/CardAccess/CardSecurity style content with maximum recursion depth and node count limits.
- Added checked high-tag-number parsing so malformed ASN.1 tags are rejected instead of risking integer overflow.
- Added regression tests for excessive ASN.1 nesting and overflowing high-tag-number encodings.

Security conclusion:

- This pass did not find evidence of a realistic "break into the device" path in the fork's decryption layer. The more plausible malicious-chip risks are denial of service, scan failure, excessive memory/time usage, parser rejection paths, or triggering downstream platform/native parsers with malformed but bounded inputs. The transport and ASN.1 hardening above closes the concrete malformed-response and parser gaps found in this pass.

Verification:

- iOS Simulator package tests passed on iPhone 17 Pro, iOS 26.5:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.5'
  ```

  Result: 153 tests passed.
- Required generic iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  This reran the required iOS build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and risky-diagnostics search. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.
- `git diff --check` passed.

Remaining follow-up:

- Image decoding remains a host-app/platform-parser boundary. The fork bounds DG2/DG7 image data and can skip DG2 via `PassportPhotoPolicy.skip`, but any app that displays the face image ultimately hands chip-controlled image bytes to Apple's image decoders. Keep photo reads opt-in for workflows that need them, avoid decoding off the main path when not needed, and stay current on iOS security updates.
- CMS/X.509 parsing remains a native OpenSSL boundary for SOD/CardSecurity verification. The fork keeps this internal and privacy-safe, but malformed certificate/CMS input is still parsed by the pinned OpenSSL package. Keep the OpenSSL package pinned/current and avoid exposing raw certificate/parser APIs to apps.
- Real-device testing remains required for actual NFC behavior, including cancellation, timeout, connection loss, and malformed/unsupported passport-chip responses where test hardware is available.

### 2026-06-21 Native Parser Boundary Hardening

Completed:

- Added explicit size guards before chip-controlled PKCS7/CMS DER and SubjectPublicKeyInfo DER blobs are handed to OpenSSL. Empty native-parser inputs and inputs above the fork's NFC response budget are rejected before `BIO`/`d2i_*` parsing.
- Routed DG14 Chip Authentication public-key parsing through the guarded `OpenSSLUtils.readPublicKey(data:)` helper instead of calling `d2i_PUBKEY` directly.
- Added a sanity cap to OpenSSL shared-secret derivation output before allocating the derived secret buffer.
- Reused DG2's JPEG/JPEG2000 allowlist at UIKit decode time, not only parse time, so manually constructed or stale model data cannot bypass the parser guard before `UIImage(data:)`.
- Added a matching DG7 decode-time guard. DG7 still preserves bounded signature-image bytes for model/status behavior, but only known bounded JPEG/JPEG2000 payloads are submitted to UIKit for image decoding.
- Added focused tests for oversized and empty OpenSSL parser inputs, oversized Chip Authentication public-key security info, and arbitrary DG7 signature bytes not being decoded as `UIImage`.

Security conclusion:

- These changes reduce the remaining malformed-chip attack surface by failing closed before native OpenSSL/UIKit parser boundaries see unreasonable or format-unknown chip-controlled data. They do not eliminate the need to keep iOS and the pinned OpenSSL package current, but the package now has explicit Swift-side guardrails at each identified fork-owned boundary.

Verification:

- iOS Simulator package tests passed on iPhone 17 Pro, iOS 26.5:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17 Pro,OS=26.5'
  ```

  Result: 157 tests passed.
- Required generic iOS package build passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  This reran the required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and risky-diagnostics search. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL/native parser type names, image model field names, or redacted diagnostic events.
- `git diff --check` passed.
- Targeted scan of changed files found no new runtime logging sink, clipboard/network persistence, raw export API, or sensitive diagnostic surface. Remaining hits are expected native parser API names, image model field names, privacy documentation, and negative-test fixtures.

### 2026-06-21 CI Runner Fix

Completed:

- Investigated the failed GitHub Actions run for commit `9becfe9`. The release checklist failed before source compilation because `macos-15` selected Xcode 16.4 / Swift tools 6.1, while this fork's package manifest requires Swift tools 6.3.
- Updated `.github/workflows/ios-package.yml` to run on `macos-26`, whose hosted runner image includes the Xcode 26 toolchain needed by the Swift 6.3 package.
- Updated `actions/checkout` from `v4` to `v5` to avoid the Node 20 deprecation warning on current GitHub-hosted runners.

Verification:

- Local release checklist passed after the CI workflow edit:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

Remaining follow-up:

- Push the branch and confirm the replacement GitHub Actions run passes on `macos-26`.

### 2026-06-21 Privacy Fork Tag 2

Completed:

- Confirmed the previously published annotated tag `notary-2.3.1-privacy.1` still points to commit `90b7d13`, before the OpenSSL pin, Swift 6.3 migration, parsing/performance cleanup, repository organization follow-up, and CI runner fix.
- Chose a new annotated tag, `notary-2.3.1-privacy.2`, instead of moving the published `notary-2.3.1-privacy.1` tag.

Verification:

- Local tag inspection confirmed `notary-2.3.1-privacy.1` is annotated and resolves to `90b7d13`.
- Remote tag inspection confirmed `origin/notary-2.3.1-privacy.1` also resolves to `90b7d13`.

Remaining follow-up:

- Push `notary-2.3.1-privacy.2` after creating it on the documented release commit.

### 2026-06-21 Fork Branch Cleanup

Completed:

- Make the fork's `main` branch the maintained Notary/privacy release line, not a plain upstream mirror.
- Preserve the previous upstream 2.3.1 pointer as `upstream/2.3.1` before moving `main`.
- Keep app consumption on annotated `notary-*` tags. Branches are for development and maintenance; tags are for app pinning.
- Updated `readme.md` and `REPOSITORY_STRUCTURE.md` with the branch and release policy.
- Deleted the completed temporary `codex/privacy-safe-logging` branch after `main` was safely updated.

Rationale:

- The previous `origin/main` pointed to upstream `2.3.1` at `7dfc19c`, which did not expose the Notary-specific privacy APIs used by the app.
- The compatible Notary release line was on `codex/privacy-safe-logging`, making the repository unintuitive and easy for package consumers to misuse.

Verification:

- `origin/main` now resolves to the maintained Notary/privacy line at `de3ca00`.
- GitHub remote `HEAD` points to `refs/heads/main`, which now resolves to `de3ca00`.
- `origin/upstream/2.3.1` resolves to the previous upstream mirror commit `7dfc19c`.
- `notary-2.3.1-privacy.2` remains the latest app-consumption tag and resolves to `12d1aea`.
- `origin/codex/privacy-safe-logging` no longer exists.

Follow-up process decision:

- Expanded `AGENTS.md` Git and release hygiene instructions so future agents keep `main` as the maintained Notary/privacy line, preserve upstream snapshots under explicit branches, delete completed temporary branches, avoid moving published app-consumption tags, and verify local/remote refs before and after branch topology changes.

### 2026-06-21 DG7 Image Retention Guard

Completed:

- Found a parser consistency gap during a broad bug/security pass: DG7 signature/mark image parsing bounded item size, and `getImage()` refused unknown image headers before UIKit decode, but the parser could still retain arbitrary non-image DG7 byte items in `imageData`/`imageDataItems`.
- Hardened `DataGroup7.parse(...)` so non-empty DG7 image items must pass the same JPEG/JPEG 2000 header allowlist before being retained. Empty DG7 image items remain accepted when the declared image count matches, so chips with no signature/mark payload can still parse as "no image present."
- Hardened DG7 structural validation so the declared image count must be a single byte and must match the number of parsed `5F43` image items.
- Fixed the DG7 compatibility projection so empty `5F43` items do not count as signature-image presence, and `DataGroup7.imageData` uses the first non-empty validated image item when an issuer includes empty placeholders before a real image.
- Updated DG7 parser tests so valid multi-image fixtures use synthetic JPEG-like image headers, arbitrary DG7 byte items are rejected before retention, and declared image-count mismatches are rejected.
- Updated README and threat model wording to document DG7 image-header validation before byte retention or decode, removed literal MRZ/access-key examples from README guidance, and replaced old troubleshooting text that referenced low-level status words with privacy-safe typed-failure guidance.

Verification:

- Focused iOS Simulator parser/result tests passed after the empty-placeholder presence fix:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 128 tests passed.
- iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 158 tests passed after the initial DG7 guard, and 164 tests passed after the follow-on empty-placeholder presence fix.
- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and risky-diagnostics search completed successfully after the initial DG7 guard and again after the empty-placeholder presence fix. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.

Remaining follow-up:

- Real-device validation remains required for passports that contain DG7 signature/mark images, especially to confirm the stricter header validation matches observed issuer data.

### 2026-06-21 DG12 Image Retention Guard

Completed:

- Found the same malformed-image retention class in DG12 after the DG7 pass: DG12 front/rear document image fields were retained as raw byte arrays without explicit size or image-header validation.
- Hardened DG12 front/rear image parsing so non-empty `5F1D` and `5F1E` values must be bounded JPEG/JPEG 2000 payloads before being retained.
- Updated the model privacy-cleanup fixture to use synthetic JPEG-like DG12 image values.
- Added focused parser tests proving arbitrary and oversized DG12 image values are rejected before retention.
- Updated README and threat model wording so the documented image-boundary guard covers DG2, DG7, and DG12.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 56 tests passed.

Remaining follow-up:

- Real-device validation remains required for passports that contain DG12 front/rear image fields, especially to confirm the JPEG/JPEG 2000 allowlist matches observed issuer data.

### 2026-06-21 DG11/DG12 Text Retention Guard

Completed:

- Continued the malformed-chip/parser pass after the DG7 and DG12 image-retention fixes, focusing on chip-controlled text fields that are decoded into retained Swift strings.
- Added explicit 64 KiB per-field text decode limits to DG11 and DG12 before values are retained as strings. This keeps normal issuer text, multilingual UTF-8, UTF-16, Latin-1, and nested DG12 person-details support, while failing closed on unreasonable text payloads.
- Capped DG12's local nested-TLV high-tag parsing and changed nested-length checks to use remaining-length arithmetic. Malformed nested person-details values still fall back to bounded plain-text decoding for compatibility.
- Added focused parser tests proving oversized DG11/DG12 text values are rejected and malformed nested DG12 tags remain bounded without trapping or exposing raw diagnostics.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 59 parser tests passed.
- Focused iOS Simulator parser/result tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 128 tests passed.
- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 162 tests passed.
- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and risky-diagnostics search completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.

Remaining follow-up:

- Real-device validation remains required before broadening compatibility claims, especially for issuer-specific DG11/DG12 optional text encodings.

### 2026-06-21 Face Image Result Format Guard

Completed:

- Found a public-result correctness mismatch during an API projection pass: DG2 image retention validates payloads by JPEG/JPEG 2000 byte header, but `PassportChipImageResult.format` and `mimeType` were derived from the ISO face-image metadata byte. If an issuer supplied inconsistent metadata, the app-facing result could label a JPEG 2000 payload as JPEG, or vice versa.
- Changed `PassportChipImageResult` to derive `format` and `mimeType` from the already validated image bytes. The original DG2 metadata remains available internally through `DataGroup2.imageDataType`, but the public sensitive image result now describes the bytes it actually returns.
- Added focused synthetic parser/result tests for JPEG and JPEG 2000 payloads whose metadata byte intentionally disagrees with the retained image header.
- Updated README photo-result guidance to document that public image format metadata follows the validated bytes.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 63 parser tests passed. An intermediate failure exposed a synthetic DG2 fixture offset bug in the new tests; the fixture was corrected and the focused test suite then passed.
- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 166 tests passed.
- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and risky-diagnostics search completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.
- Final changed-file whitespace and risky-pattern scans passed. The targeted scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in the changed sources. Remaining hits are expected README/threat-model/plan privacy wording and synthetic parser fixtures.

Remaining follow-up:

- Continue cross-checking app-facing result fields against parser/source metadata so safe projections do not overstate or mislabel chip-controlled values.

### 2026-06-21 BAC Challenge Length Guard

Completed:

- Continued the trap/correctness pass into BAC and secure-messaging boundaries after the parser/API projection work.
- Found that `BACHandler.authentication(rnd_icc:)` accepted chip challenge byte arrays of any length before constructing the BAC mutual-authentication command. BAC requires an 8-byte ICC challenge; malformed lengths could otherwise be mixed into handler state and command construction, failing later depending on crypto output shape.
- Hardened BAC command construction to require an exact 8-byte ICC challenge before retaining challenge bytes or generating terminal random/session material.
- Removed a duplicate `rnd_icc` assignment in the same path.
- Added a focused regression test for empty, short, and long BAC challenges, including a state-retention check proving rejected challenge bytes are not kept on the handler.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 37 core tests passed.
- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 167 tests passed.
- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and risky-diagnostics search completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, or redacted diagnostic events.
- Final changed-file whitespace and risky-pattern scans passed. The targeted scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in the changed sources. Remaining hits are expected README/threat-model/plan privacy wording, synthetic parser fixtures, BAC/session-key identifiers, and negative-test fixtures.

Remaining follow-up:

- Continue trap/correctness auditing across remaining authentication and NFC transport paths, especially chip-controlled response parsing and retry boundaries.

### 2026-06-21 Initial File Read Header Guard

Completed:

- Continued the NFC transport correctness pass after the BAC challenge guard, focusing on chip-controlled file lengths and read offsets.
- Found that `TagReader.selectFileAndRead(...)` read only four initial bytes before decoding the ASN.1 file length. That covered short and two-byte long-form lengths, but the shared ASN.1 helpers and `DataGroup` parser already accept three- and four-byte long-form lengths. A large but otherwise valid LDS file could therefore fail before chunked reading began.
- Changed the initial file read to fetch enough bytes for the tag plus the largest supported ASN.1 length field, and centralized initial-header parsing in a tested helper.
- Preserved body bytes already returned with the initial header read instead of discarding and rereading them from the next offset.
- Added a chip-controlled advertised-file-size guard before `reserveCapacity` and chunked reading. Advertised LDS files over 24 MiB are rejected as malformed before allocation pressure or long read loops.
- Added focused transport-helper tests for short-form body retention, three-byte long-form length support, and oversized advertised length rejection.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 40 core tests passed.
- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 170 tests passed.
- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: required iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and risky-diagnostics search completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, NFC transport type names, or redacted diagnostic events.
- Final changed-file whitespace and risky-pattern scans passed. The targeted scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in the changed sources. Remaining hits are expected README/threat-model/plan privacy wording, synthetic parser fixtures, BAC/session-key identifiers, NFC/APDU type names, and negative-test fixtures.

Remaining follow-up:

- Continue trap/correctness auditing across remaining authentication, secure-messaging, and NFC retry paths.

### 2026-06-21 Public Surface And Filesystem Sink Guard

Completed:

- Continued the bug/security pass from the public API and module-boundary angle.
- Re-reviewed the external API surface probe. The safe consumer still exercises the intended app-facing surface, while the unsafe consumer asserts low-level raw model, NFC, BAC/PACE, secure-messaging, data-group parser, SecurityInfo, and OpenSSL helper types remain unavailable to external app targets.
- Found an unused `FileManager.documentDir` helper in parsing utilities. It was not called, but it pointed at the user Documents directory and was inconsistent with this fork's no-implicit-persistence posture.
- Removed the unused filesystem helper.
- Tightened `scripts/privacy_scan.sh` so any future `FileManager.default` production source usage, not only create/write calls, becomes release-blocking pending privacy review.
- Aligned the broad release-check risky-pattern search with the stricter filesystem-sink vocabulary.

Verification:

- Tightened privacy scan passed:

  ```sh
  scripts/privacy_scan.sh
  ```

  Result: no raw production diagnostics, risky sinks, sensitive diagnostic vocabulary, or removed raw import/export APIs found in production sources.
- External API surface check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/api_surface_check.sh
  ```

  Result: the safe external consumer compiled and the unsafe external consumer continued to fail for raw/internal NFC, authentication, parser, secure-messaging, and OpenSSL helper types.
- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and broad risky-diagnostics search completed. The risky-pattern output was reviewed as expected documentation/test/internal identifier hits, with no new production filesystem persistence sink after removing `FileManager.documentDir`.
- Final whitespace, changed-file, and filesystem sink scans passed. `git diff --check` produced no output. The targeted changed-file scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in changed production sources. Remaining hits are expected README/threat-model/plan privacy wording, synthetic test fixtures, BAC/session-key identifiers, NFC/APDU type names, script scan patterns, and negative-test fixtures.
- A narrow production sink scan found only the existing typed redacted `eventLogger.log(...)` calls. A filesystem-helper scan found `FileManager.default`, `documentDir`, and `documentsDirectory` only in this planning document after the unused helper removal.

Remaining follow-up:

- Continue trap/correctness auditing across remaining authentication, secure-messaging, and NFC retry paths.

### 2026-06-21 Secure Messaging Protected Response Fail-Closed Pass

Completed:

- Continued the bug/security pass from the secure-messaging response parser angle.
- Tightened `SecureMessaging.unprotect(rapdu:)` so a successful outer status requires a well-formed protected DO'99 status object instead of converting missing, truncated, or malformed protected status data into synthetic response status words.
- Tightened DO'87 validation so encrypted response data must include the required content marker plus non-empty encrypted bytes aligned to the active cipher block size before MAC verification or decryption.
- Tightened DO'8E validation so response checksum objects must carry the expected 8-byte MAC length.
- Updated regression coverage for empty successful protected responses, truncated/malformed DO'99, empty DO'87, unaligned DO'87, malformed DO'8E, and trailing bytes after DO'8E.
- Updated the threat model to call out fail-closed Secure Messaging handling for missing, truncated, malformed, or inconsistent protected response objects.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 44 core tests passed.
- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 174 tests passed.
- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and broad risky-diagnostics search completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic secure-messaging fixtures, internal APDU/key identifiers, OpenSSL type names, NFC transport type names, or redacted diagnostic events.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A changed-file scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in the changed production sources. Remaining hits are expected threat-model/plan privacy wording, internal APDU/key identifiers, and synthetic secure-messaging negative-test fixtures. A narrow production sink scan over the touched source files returned no matches.
- A direct-index scan of `SecureMessaging.swift` now leaves only guarded protocol-shape checks on non-empty response data and fixed-size DO'99 bytes.

Remaining follow-up:

- Continue trap/correctness auditing across remaining authentication and NFC retry paths.

### 2026-06-21 GET RESPONSE Length Normalization Pass

Completed:

- Continued the NFC transport retry/chaining audit after the secure-messaging protected-response pass.
- Found that `TagReader.send(...)` forwarded `SW1=0x61, SW2=0x00` into CoreNFC as `expectedResponseLength: 0` for the follow-up GET RESPONSE command. In ISO 7816 short-length semantics, `61 00` asks the terminal to request the maximum short response length, not zero bytes.
- Added `TagReader.getResponseLength(sw2:)` so `SW2=0x00` maps to 256 and nonzero values continue to map directly.
- Updated the GET RESPONSE loop to use the normalized length while preserving the existing chained-response segment and byte-budget guards.
- Added focused regression coverage for `61 00`, `61 01`, `61 A0`, and `61 FF` length normalization.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 45 core tests passed.
- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 175 tests passed.
- Full release check passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, external API surface probe, privacy scan, whitespace check, NFC boundary check, and broad risky-diagnostics search completed successfully. Risky-pattern hits were reviewed as expected documentation, negative tests, synthetic fixtures, internal APDU/key identifiers, OpenSSL type names, NFC transport type names, or redacted diagnostic events.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A changed-file scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in changed production sources. Remaining hits are expected plan privacy wording, internal APDU/key identifiers, and synthetic test fixtures. A narrow production sink scan over touched source files returned no matches, and a `TagReader.swift` trap/direct-index scan returned no matches.

Remaining follow-up:

- Continue trap/correctness auditing across remaining authentication and NFC retry paths.

### 2026-06-21 MSE Algorithm Identifier Fail-Closed Pass

Completed:

- Continued the authentication command-construction audit after the GET RESPONSE transport pass.
- Found that PACE and Chip Authentication MSE Set AT command construction used `oidToBytes(..., replaceTag: true)` directly. If an invalid or unencodable algorithm OID reached this layer, encoding collapsed to an empty byte array and the reader could construct an MSE APDU without the required algorithm identifier.
- Added `TagReader.mseAlgorithmIdentifierData(oid:)` so invalid MSE algorithm identifiers throw `InvalidDataPassed` before APDU construction or NFC transmission.
- Routed both `sendMSESetATMutualAuth(...)` and `sendMSESetATIntAuth(...)` through the checked encoder.
- Added focused regression coverage proving invalid OIDs are rejected and valid PACE/Chip Authentication OIDs are encoded with the required private `0x80` algorithm tag.

Verification:

- Focused iOS Simulator core tests passed after correcting an intermediate test-only constant lookup:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 47 core tests passed.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 177 tests passed.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. The changed-file scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in changed production sources. Remaining hits are expected plan privacy wording, internal APDU/NFC type names, and synthetic secure-messaging test fixtures. A narrow production sink scan over touched source files returned no matches, and a `TagReader.swift` trap/direct-index scan returned no matches.

Remaining follow-up:

- Continue trap/correctness auditing across remaining authentication and NFC retry paths.

### 2026-06-21 CardSecurity SignedData Structure Guard

Completed:

- Continued the parser and verification-input audit from the SOD/SecurityInfos surface.
- Found that `SecurityInfosParser.signedEncapsulatedContent(from:)`, used by `CardSecurity`, extracted encapsulated security infos from a broad two-child sequence without first confirming the CMS content type was `signedData` or that the signed-data body was inside the required explicit `[0]` wrapper.
- Hardened `SecurityInfosParser.signedEncapsulatedContent(from:)` to require the CMS `signedData` object identifier (`1.2.840.113549.1.7.2`) and the explicit `0xA0` wrapper before accepting nested signed data.
- Reworked `SecurityInfosParser` to avoid numeric ASN.1 child subscripts in this path, using named first/next child nodes instead so malformed structures stay on guarded optional paths.
- Added malformed CardSecurity regression tests that reject an unsigned CMS content OID and reject a missing explicit signed-data wrapper, while preserving the valid signed CardSecurity fixture.

Verification:

- Focused iOS Simulator parsing tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 65 parsing tests passed.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 179 tests passed. Xcode emitted the existing AppIntents metadata extraction warning (`No AppIntents.framework dependency found`), which is a toolchain metadata warning for this package test host and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. The changed-file scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in changed production sources. Remaining hits are expected plan privacy wording and synthetic parser fixtures. A narrow production sink scan over touched SecurityInfos/CardSecurity sources returned no matches, and the parser trap/direct-index scan returned no matches.

Remaining follow-up:

- Continue direct-index and malformed-ASN.1 auditing across remaining SOD, SecurityInfos, and authentication retry paths.

### 2026-06-21 SOD Parser Fail-Closed Cleanup Pass

Completed:

- Continued malformed ASN.1 and cleanup-state auditing on the SOD/passive-authentication path.
- Found that `SOD` retained its parsed ASN.1 tree as an implicitly unwrapped optional while `removeSensitiveDataForPrivacy()` deliberately nils that tree. Calling SOD accessors after privacy cleanup could therefore trap instead of returning a controlled parse failure.
- Changed `SOD.asn1Root` to an ordinary optional and made `signedDataItem()` fail closed with `UnableToExtractSignedDataFromPKCS7` when the parsed tree is unavailable or malformed.
- Reworked SOD CMS and structured LDS Security Object parsing to use named optional child nodes instead of constant numeric ASN.1 child subscripts. This keeps malformed structures on guarded paths and reduces future crash-prone parser assumptions.
- Added focused regression coverage proving SOD accessors fail closed after privacy cleanup without exposing APDU wording or trapping.

Verification:

- Focused iOS Simulator parsing tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 66 parsing tests passed.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 180 tests passed. Xcode emitted the existing AppIntents metadata extraction warning (`No AppIntents.framework dependency found`), which is a toolchain metadata warning for this package test host and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Targeted SOD/model parser trap and direct-index scan returned no matches.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. The changed-file scan found no new active raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sink in changed production sources. Remaining hits are expected plan privacy wording, synthetic parser fixtures, and APDU wording assertions in privacy tests. A narrow production sink scan over touched SOD/model sources returned no matches, and the SOD/model trap/direct-index scan returned no matches.

Remaining follow-up:

- Continue malformed-ASN.1 and cleanup-state auditing in the remaining passive-authentication and certificate-helper paths.

### 2026-06-21 OpenSSL X509 Chain Ownership And Bounds Pass

Completed:

- Audited certificate and OpenSSL helper boundaries after the SOD parser cleanup pass, with attention to native ownership and malformed helper inputs.
- Found that `OpenSSLUtils.verifyTrustAndGetIssuerCertificate` called `X509_STORE_CTX_get1_chain(store)` without releasing the returned reference-counted X509 stack. This could leak native memory during repeated certificate trust verification.
- Added a scoped `OSSL_STACK_OF_X509_free` release for the copied verification chain while preserving the existing issuer-certificate return behavior.
- Tightened `OpenSSLUtils.sk_X509_value` so negative and out-of-range indices return `nil` before crossing into OpenSSL.
- Cleaned up CMAC parameter construction so the duplicated cipher-name pointer is guarded and released directly, avoiding direct array-index cleanup in native parameter ownership code.
- Extended OpenSSL stack-helper regression coverage for nil pointer and invalid index calls.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 47 core tests passed. Xcode emitted the existing AppIntents metadata extraction warning (`No AppIntents.framework dependency found`), which is a package test-host/toolchain warning and not a warning from changed package code.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 180 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over touched OpenSSL/certificate sources returned no matches for raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sinks.
- The changed-file sensitive-pattern scan found expected plan privacy wording and synthetic secure-messaging/test-vector material only. The touched OpenSSL/certificate trap and direct-index scan returned no matches after the CMAC parameter cleanup.

Testing note:

- The stack bounds helper now has direct regression coverage. The copied-chain ownership release is covered by build and helper-boundary exercise; direct native allocation instrumentation is not practical in the current XCTest target.

Remaining follow-up:

- Continue native-helper auditing across the remaining OpenSSL public-key construction and verification paths.

### 2026-06-21 OpenSSL Public-Key Helper Fail-Closed Pass

Completed:

- Continued native-helper auditing across the PACE/Chip Authentication public-key extraction and peer-key decoding paths.
- Found that `OpenSSLUtils.getPublicKeyData(from:)` returned an empty byte array for unsupported EVP key types. Empty bytes could be mistaken for a successful key export by callers, instead of failing closed before protocol state advances.
- Changed unsupported key types to return `nil` explicitly, tightened DH public-key byte extraction to require a positive bounded length and matching `BN_bn2bin` result, and tightened EC public-key extraction to keep OpenSSL-reported lengths within the existing public-key byte cap.
- Changed `decodePublicKeyFromBytes(pubKeyData:params:)` so only DH/DHX and EC parameter keys are accepted. Other key types now return `nil` before querying EC group-name parameters.
- Added an allocation guard for OpenSSL string parameters used while reconstructing EC public keys.
- Rechecked the final shared-secret length after OpenSSL writes it back, so a second derive call cannot silently report a zero, oversized, or buffer-inconsistent length.
- Added a focused regression test proving unsupported EVP key types fail closed for both public-key extraction and peer-key reconstruction.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 48 core tests passed. Xcode emitted the existing AppIntents metadata extraction warning (`No AppIntents.framework dependency found`), which is a package test-host/toolchain warning and not a warning from changed package code.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 181 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over touched OpenSSL/test sources returned no matches for raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sinks.
- The changed-file sensitive-pattern scan found expected plan privacy wording and synthetic secure-messaging/test-vector material only. The source-only OpenSSL trap and direct-index scan returned no matches; the wider source/test trap scan found only existing direct-index assertions in old ASN.1 length tests.

Remaining follow-up:

- Continue native-helper auditing across remaining OpenSSL signature and certificate metadata paths.

### 2026-06-21 OpenSSL Signature Bounds Pass

Completed:

- Continued native-helper auditing across Active Authentication and SOD signature verification helpers.
- Found that signature verification/recovery helpers accepted chip-controlled signature byte arrays without an explicit size cap. ECDSA plain-signature conversion could allocate from a very large signature, and RSA signature recovery trusted the first OpenSSL-reported output length before allocation.
- Added a 64 KiB signature-input cap for RSA signature recovery, generic digest verification, and ECDSA plain-signature conversion.
- Added a 64 KiB recovered/DER signature-output cap before allocating RSA recovery output or DER-encoded ECDSA signature bytes.
- Tightened RSA recovery to recheck the final output length after OpenSSL writes it back.
- Tightened ECDSA plain-signature setup so failed BIGNUM allocation or failed ownership transfer returns `false` instead of continuing with a partially built `ECDSA_SIG`.
- Added focused regression coverage proving oversized signature inputs are rejected before native signature work.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 49 core tests passed. Xcode emitted the existing AppIntents metadata extraction warning (`No AppIntents.framework dependency found`), which is a package test-host/toolchain warning and not a warning from changed package code.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 182 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over touched OpenSSL/test sources returned no matches for raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sinks.
- The changed-file sensitive-pattern scan found expected plan privacy wording and synthetic secure-messaging/test-vector material only. The source-only OpenSSL trap and direct-index scan returned no matches; the wider source/test trap scan found only existing direct-index assertions in old ASN.1 length tests.

Remaining follow-up:

- Continue certificate metadata output and BIO conversion auditing.

### 2026-06-21 OpenSSL Certificate Metadata and BIO Bounds Pass

Completed:

- Continued native-helper auditing across certificate metadata formatting and BIO conversion helpers.
- Found that certificate serial extraction used `ASN1_INTEGER_get`, which can truncate or misrepresent X.509 serial numbers that do not fit in a platform `long`.
- Changed serial formatting to convert through OpenSSL BIGNUM bytes, reject negative or oversized serial values, and preserve full positive serial values without narrowing.
- Added a bounded BIO string conversion path so OpenSSL error text, PEM conversion, certificate names, and ASN.1 time strings cannot allocate from unchecked BIO lengths.
- Checked BIO read/write results in PKCS7 certificate extraction, CMS encapsulated-content extraction, PEM conversion, and public-key parsing paths.
- Tightened certificate fingerprint, name, and ASN.1 time helpers so failed OpenSSL calls return `nil`/empty results instead of formatting unchecked or partial data.
- Added focused synthetic regression coverage for oversized BIO string rejection and full-width X.509 serial formatting.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 51 core tests passed after resolving an initial test-expression compiler diagnostic issue and a too-skeletal synthetic certificate fixture.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 184 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over touched OpenSSL/X509/test files returned no matches for raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sinks.
- The source-only OpenSSL/X509 trap and direct-index scan returned no matches. The changed-file sensitive-pattern scan found expected plan privacy wording and synthetic secure-messaging/test-vector material only.

Remaining follow-up:

- Continue auditing any remaining native OpenSSL verification and certificate trust error paths for bounded output and privacy-safe failures.

### 2026-06-21 OpenSSL Trust Store Load Fail-Closed Pass

Completed:

- Continued auditing native OpenSSL verification and certificate trust error paths.
- Found that `verifyTrustAndGetIssuerCertificate(x509:CAFile:)` called `X509_LOOKUP_ctrl(... X509_L_FILE_LOAD ...)` for the master-list file but ignored the return code. A missing, unreadable, or malformed CA file could therefore fall through into certificate verification and report a later generic trust failure instead of failing closed at master-list load.
- Consolidated trust-store creation onto the checked `makeX509Store(CAFile:)` helper so CA lookup creation and master-list loading are validated before `X509_STORE_CTX` verification begins.
- Kept the existing explicit-EC-parameters compatibility callback in the shared store helper.
- Added a focused synthetic certificate regression proving missing master-list files fail with `Unable to load trusted certificates` before certificate-chain verification.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 52 core tests passed. The first attempt exposed that the OpenSSL package does not expose the `EVP_RSA_gen` macro to Swift; the synthetic certificate fixture was changed to use the repo's existing EC key-generation helper and then passed.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 185 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over touched OpenSSL/test files returned no matches for raw logging, print diagnostics, direct `Logger`, `os_log`, clipboard, persistence, network, or raw diagnostic sinks.
- The source-only OpenSSL trap and direct-index scan returned no matches. The changed-file sensitive-pattern scan found expected plan privacy wording and synthetic secure-messaging/test-vector material only.

Remaining follow-up:

- Continue auditing manual SOD verification fallback and CMS trust/no-trust behavior for exact fail-closed semantics and privacy-safe errors.

### 2026-06-21 SOD Fallback Error Preservation Pass

Completed:

- Continued auditing manual SOD verification fallback and CMS trust/no-trust behavior.
- Found that when both SOD signature verification paths failed, `NFCPassportModel.ensureReadDataNotBeenTamperedWith(...)` intentionally fell back to unsigned encapsulated SOD content for data-group hash comparison but dropped the signature-verification error. That allowed data-group hash status to remain useful, but safe verification details could report a generic attempted failure instead of the more accurate invalid SOD signature reason.
- Preserved the SOD signature-verification error before falling back to unsigned encapsulated content, while keeping the hash-comparison fallback behavior intact.
- Reset EF.CardSecurity verification trust flags at the start of each `verifySignature(...)` attempt so failed verification cannot leave stale `signatureVerified` or `signerTrusted` state from an earlier attempt.
- Added a focused synthetic SOD regression proving that an unverifiable SOD signature with matching DG1 hashes reports `sodSignatureDetail` as failed/signature-invalid while `dataGroupHashDetail` can still pass.

Verification:

- Focused iOS Simulator parsing tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 67 parsing tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 186 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over touched model/CardSecurity sources returned no matches. The changed-file sensitive-pattern scan found expected plan privacy wording and synthetic parser fixtures only. A direct-index/trap scan over touched production sources found only an existing safe `names[0]` access backed by Swift `components(separatedBy:)`, which always returns at least one element.

Remaining follow-up:

- Continue auditing SOD/CMS and EF.CardSecurity trust paths for any remaining swallowed trust failures or misleading safe verification details.

### 2026-06-21 Chip Authentication Chunking Trap-Safety Pass

Completed:

- Continued trap-safety auditing from the chip-authentication command-chaining boundary.
- Found that `ChipAuthenticationHandler.chunk(data:segmentSize:)` used `stride(..., by: segmentSize)` without guarding the segment size. A zero or negative segment size would trap if an internal refactor or future caller passed an invalid value.
- Made chunking fail closed to an empty segment list for empty data or non-positive segment sizes.
- Made `handleGeneralAuthentication()` fail with typed `ChipAuthenticationFailed` if no command-chaining segment is available, rather than reaching `removeFirst()` on an empty array.
- Marked the pure chunk helper `nonisolated` so it can be tested and used without inheriting the handler's `@MainActor` isolation.
- Added focused regression tests for zero, negative, empty, and normal remainder-preserving chunking behavior.

Verification:

- Focused iOS Simulator core tests passed after resolving the initial Swift actor-isolation compiler diagnostic by marking the pure static helper `nonisolated`:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 54 core tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 188 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over the touched Chip Authentication source found no raw logging, print diagnostics, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, runtime trap, force-unwrap, or force-cast sinks. Changed-file sensitive-pattern hits were expected plan privacy wording, existing secure-messaging test vectors, and internal APDU/key type names.

Remaining follow-up:

- Continue trap/correctness auditing around remaining command-chaining, PACE, and Chip Authentication state transitions.

### 2026-06-21 Negative Integer Encoding Guard Pass

Completed:

- Continued command-encoding boundary auditing around integer-to-byte helpers used by secure messaging and authentication command builders.
- Found that `intToBin(_:)` and `intToBytes(val:removePadding:)` accepted negative integers and encoded them as two's-complement bytes, which could turn invalid internal state into `0xFF`-style command data.
- Made both helpers fail closed to an empty byte array for negative values while preserving existing non-negative big-endian behavior.
- Added focused regression coverage for negative `intToBin` and `intToBytes` inputs alongside the existing byte/integer helper tests.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 54 core tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 188 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over the touched utility source found no raw logging, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, runtime trap, force-unwrap, or force-cast sinks. Changed-file sensitive-pattern hits were expected plan privacy wording, existing secure-messaging test vectors, and internal APDU/key type names.

Remaining follow-up:

- Continue auditing PACE and Chip Authentication state transitions for swallowed parse failures, misleading error mapping, and any other command-boundary assumptions.

### 2026-06-21 MSE Key Identifier Guard Pass

Completed:

- Continued command-boundary auditing after the negative integer encoding guard.
- Found that Chip Authentication MSE key identifiers still used raw integer-to-byte output at the APDU construction layer. A negative key identifier would now encode to an empty byte array and could still be wrapped as an empty `DO 84` instead of being rejected.
- Added `TagReader.mseKeyIdentifierData(keyId:)` to centralize MSE key-id encoding, preserve nil/zero omission behavior, and reject invalid negative identifiers before APDU construction or NFC transmission.
- Routed both AES MSE Set AT and DESede MSE KAT Chip Authentication paths through the shared key-id encoder.
- Added focused regression coverage for negative, nil, zero, and positive key identifier encoding.

Verification:

- Focused iOS Simulator core tests passed after resolving an initial Swift compile diagnostic by making optional `Data` construction explicit:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 57 core tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 191 tests passed. Xcode emitted the existing AppIntents metadata extraction warning, which remains a package test-host/toolchain warning and not a warning from changed package code.

- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over touched NFC and Chip Authentication sources found no raw logging, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, runtime trap, force-unwrap, or force-cast sinks. Changed-file sensitive-pattern hits were expected plan privacy wording, existing secure-messaging test vectors, and internal APDU/key type names.

Remaining follow-up:

- Continue auditing PACE and Chip Authentication state transitions for swallowed parse failures, misleading error mapping, and any remaining APDU construction assumptions.

### 2026-06-21 DG2 Declared Facial Record Boundary Pass

Completed:

- Continued malformed-chip parser auditing from the DG2 ISO/IEC 19794-5 facial image boundary.
- Found that the single-facial-record path read the declared facial-record data length but still used the full biometric data object as the record end. Undeclared trailing bytes after a valid image header could therefore be retained as part of `imageData`.
- Made the single-record path reject the unsafe declared-length-shorter-than-container case before image retention, while preserving compatibility with existing cut-down synthetic DG2 fixtures whose declared facial-record length is longer than the truncated fixture bytes.
- Added focused regression coverage proving a DG2 facial record with undeclared trailing bytes throws `InvalidASN1Structure` and does not replace the previously retained valid image bytes.

Verification:

- An initial focused parsing run failed after an exact-length check rejected existing cut-down synthetic DG2 fixtures. The guard was narrowed to reject only the unsafe direction where declared facial-record length is shorter than the biometric data object, preserving fixture compatibility while preventing undeclared image-byte retention.
- Focused iOS Simulator parsing tests passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests` completed 68 tests successfully. The earlier failed run also emitted Xcode's post-failure simulator diagnostics collection message about `simctl` lookup; the subsequent passing run did not indicate an in-repo warning.
- Full iOS Simulator package tests passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'` completed 192 tests successfully. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Release verification passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh` completed package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests successfully. Risky-pattern output remained limited to expected docs, tests, and internal type-name matches.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. Narrow scans over the touched DG2 parser, focused parsing tests, and planning document found no active production raw logging or diagnostic sinks in the touched DG2 source/test files; sensitive-pattern hits were expected synthetic fixture bytes, APDU/privacy wording, and plan documentation.

Remaining follow-up:

- Continue auditing PACE parse/error boundaries and remaining parser length fields where declared sizes may diverge from retained bytes.

### 2026-06-21 Recognized SecurityInfo Fail-Closed Parsing Pass

Completed:

- Continued the PACE/Chip Authentication state-transition audit from the SecurityInfos parser boundary.
- Found that recognized PACE, Chip Authentication, Active Authentication, and Chip Authentication public-key records could be built from malformed typed fields. Missing or malformed required INTEGER values were converted to version `-1`, malformed optional identifiers were treated as absent, and invalid recognized public-key records could be skipped as `nil`.
- Changed the recognized SecurityInfo factory to fail closed with `InvalidASN1Structure` when required fields or typed optional fields are malformed. Unknown OIDs remain preserved as redacted `UnknownSecurityInfo` metadata.
- Updated the shared parser to propagate recognized-record parse failures instead of silently omitting those entries.
- Added focused parser regressions for malformed recognized required fields, malformed recognized optional fields, and invalid/oversized Chip Authentication public-key info. Updated the diagnostics test expectations to match the stricter fail-closed contract.

Verification:

- An initial focused parser run failed to compile because an existing diagnostics test still called `SecurityInfo.getInstance(...)` as a nonthrowing optional-returning helper. The test was updated to assert `InvalidASN1Structure` for the stricter fail-closed behavior.
- Focused iOS Simulator parser/diagnostics tests passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests` completed 137 tests successfully. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Full iOS Simulator package tests passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'` completed 194 tests successfully. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Release verification passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh` completed package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests successfully. Risky-pattern output remained limited to expected docs, tests, and internal type-name matches.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. Narrow scans over the touched SecurityInfo parser sources found no raw logging, print diagnostics, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, runtime trap, force-unwrap, or force-cast sinks; changed-file sensitive-pattern hits were expected plan privacy wording, negative privacy-test fixtures, synthetic parser fixtures, and internal APDU/key terminology.

Remaining follow-up:

- Continue auditing PACE and Chip Authentication runtime error mapping after the stricter SecurityInfo parse gate, especially fallback behavior when EF.CardAccess or EF.CardSecurity contains recognized-but-malformed authentication records.

### 2026-06-21 PACE Step 4 Authentication Token Parsing Pass

Completed:

- Continued the PACE runtime correctness audit after the stricter SecurityInfo parse gate.
- Found that PACE Step 4 required the chip's authentication token (`0x86`) to be the first returned TLV record. The code already treated optional CAM data (`0x8A`) by searching the response records, so a response that carried CAM data before the token would be rejected even though the token was present.
- Added an order-independent PACE Step 4 response parser that finds the required authentication token by tag and separately returns optional encrypted CAM data.
- Replaced direct array equality for PACE authentication-token verification with a constant-time byte comparison.
- Added focused core tests for CAM-before-token response ordering, missing token rejection, and exact-token comparison behavior.

Verification:

- Focused iOS Simulator core tests passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests` completed 60 tests successfully. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Full iOS Simulator package tests passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'` completed 197 tests successfully. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Release verification passed: `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh` completed package resolution, API surface check, privacy scan, iOS build, and iOS Simulator tests successfully. Risky-pattern output remained limited to expected docs, tests, and internal type-name matches.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over the touched PACE source found no raw logging, print diagnostics, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, runtime trap, force-unwrap, or force-cast sinks. Changed-file sensitive-pattern hits were expected plan privacy wording, PACE comments, known Integrated Mapping constants, and synthetic secure-messaging/core test fixtures.

Remaining follow-up:

- Continue auditing PACE and Chip Authentication runtime fallback behavior for partially completed command sequences, especially whether retrying another Chip Authentication public key should explicitly reset secure messaging state before the next attempt.

### 2026-06-21 Chip Authentication Pending GA Segment Cleanup Pass

Completed:

- Continued the Chip Authentication runtime fallback audit after the PACE Step 4 parsing pass.
- Found that the AES Chip Authentication path could retain pending General Authentication command segments if the command-chaining send failed after only part of the segment list had been consumed. That retained transient state could survive until a later retry, overwrite, or handler cleanup.
- Scoped pending General Authentication segments with `withPendingGeneralAuthenticationSegments(...)` so the segment list is cleared on both successful and failed attempts.
- Added an internal no-tag Chip Authentication handler initializer for focused actor-isolated state tests. This is internal testability only and does not change the public reader API.
- Added focused core tests proving pending General Authentication segments are visible during an attempt and cleared after both success and thrown failure.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 62 core tests passed. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 199 tests passed. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink and sensitive-pattern scan over the touched Chip Authentication source returned no matches. Changed-file sensitive-pattern hits were expected planning-document privacy wording, existing secure-messaging test vectors, and internal APDU/key type names.

Remaining follow-up:

- Continue auditing Chip Authentication retry and secure-messaging fallback behavior for partially completed command sequences, especially whether retrying another public key should reset secure-messaging state before the next attempt.

### 2026-06-21 Secure Messaging Protect Counter Transaction Pass

Completed:

- Continued the Chip Authentication retry/fallback audit from the lower secure-messaging boundary.
- Found that `SecureMessaging.protect(apdu:)` advanced the send sequence counter before all local APDU protection work had succeeded. If local protection failed before a command was returned for NFC transmission, the host counter was still consumed even though the chip could not have consumed the matching command.
- Made APDU protection transactional for local failures: the sequence counter is still committed on successful protection, but restored to its original value when local protection throws.
- Added an internal sequence-counter accessor for focused module tests only; it is not part of the public reader API.
- Added a focused core regression proving a local protection failure does not advance the retained sequence counter.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 63 core tests passed. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Full iOS Simulator package tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'
  ```

  Result: 200 tests passed. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Release verification initially failed on `git diff --check` because the edited transaction block introduced trailing whitespace. The whitespace was removed, and release verification then passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: package resolution, privacy scan, iOS build, and iOS Simulator tests all passed. The release-check risky-pattern output contained expected documentation/test/type-name hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink and sensitive-label scan over the touched Secure Messaging source returned no matches. Changed-file sensitive-pattern hits were expected planning-document privacy wording, internal APDU type names, and existing synthetic secure-messaging test vectors.

Remaining follow-up:

- Continue auditing secure-messaging receive/error paths and Chip Authentication public-key retry behavior for exact counter and fallback semantics after protected commands have actually reached the chip.

### 2026-06-21 Secure Messaging Plain Error Counter Pass

Completed:

- Continued the secure-messaging receive/error-path audit after making APDU protection transactional.
- Found that `SecureMessaging.unprotect(rapdu:)` advanced the receive sequence counter before checking whether the chip response was a protected success response or a plain non-success status response. For plain status errors, no protected response cryptogram or MAC is consumed, so advancing the host receive counter could overstep state for callers that handle the status without immediately rebuilding secure messaging.
- Moved the plain status-error early return before the receive-counter increment. Protected success responses still advance the receive counter before MAC/decryption checks as before.
- Added a focused core regression proving an unprotected plain status error is returned without changing the retained sequence counter.

Verification:

- Focused iOS Simulator core tests passed with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests`. Result: 64 core tests passed. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Full iOS Simulator package tests passed with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'`. Result: 201 tests passed. Xcode continued to emit the existing AppIntents metadata extraction warning only.
- Release verification passed with `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`. Result: package resolution, privacy scan, iOS build, and iOS Simulator tests all passed. Release-check risky-pattern output contained expected documentation, test fixture, and type-name hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink/sensitive-label scan over the touched Secure Messaging source returned no matches. Changed-file sensitive hits were expected planning-document privacy wording, internal APDU type names/comments, and existing synthetic secure-messaging test vectors.

Remaining follow-up:

- Continue auditing malformed protected-response handling and Chip Authentication public-key retry behavior for cases where a protected command reached the chip and the safest recovery is to rebuild BAC/PACE secure messaging.

### 2026-06-21 Release Gate Simulator Test Pass

Completed:

- Continued the verification/release-hygiene audit after the secure-messaging receive-state pass.
- Found a release-gate correctness gap: recent plan entries and handoff language treated `scripts/release_check.sh` as proof that the full iOS Simulator package tests had run, but the script itself only performed an iOS package build, iOS build-for-testing, API/privacy/NFC scans, whitespace checks, and risky-pattern reporting. That could allow future release checks to pass without executing the test suite that the fork plan expects.
- Updated `scripts/release_check.sh` to run `xcodebuild test -scheme NFCPassportReader` as part of the wrapper. The simulator destination defaults to `platform=iOS Simulator,name=iPhone 17,OS=26.5` and can be overridden with `IOS_TEST_DESTINATION` for other local or CI simulator images.
- Updated `readme.md` and `THREAT_MODEL.md` so the public release checklist explicitly says the release wrapper runs the full iOS Simulator test suite.
- No Swift unit test was added for this pass because the bug was in the shell release gate itself. The regression evidence is the syntax check plus executing the updated wrapper end-to-end.

Verification:

- Shell syntax check passed: `bash -n scripts/release_check.sh`.
- Updated release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The wrapper now visibly invokes `xcodebuild test -scheme NFCPassportReader -destination "$IOS_TEST_DESTINATION"` before the API/privacy gates. Risky-pattern output remained expected documentation, synthetic-test, and internal type-name hits only.

Remaining follow-up:

- Continue code-path bug passes. The release wrapper now proves simulator tests by default, but future CI restoration should still choose an available simulator through `IOS_TEST_DESTINATION` if the default image is not installed.

### 2026-06-21 SecurityInfos Top-Level Strictness Pass

Completed:

- Continued the malformed-input acceptance audit after the release-gate verification fix, focusing on security metadata parsed from EF.CardAccess, EF.CardSecurity, and DG14.
- Found that `SecurityInfosParser.parse(_:)` silently skipped malformed top-level `SecurityInfo` entries before OID classification. A non-SEQUENCE child, a SEQUENCE without an object identifier, or a SEQUENCE without required data could disappear from the parsed result instead of causing the chip-controlled security metadata to fail closed.
- Tightened `SecurityInfosParser` so every child in the SecurityInfos SET/SEQUENCE must itself be a valid SecurityInfo SEQUENCE with an OID and required data. Unknown but well-formed OIDs are still preserved as `UnknownSecurityInfo`; malformed entries now throw `InvalidASN1Structure`.
- Added focused parser regressions proving malformed top-level SecurityInfo entries are rejected instead of skipped.

Verification:

- The first focused parser-test run exposed test-fixture compile issues because the new ASN.1 helper calls needed explicit `try`. Those were fixed before handoff.
- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 71 parser tests passed.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 202 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, and internal type-name hits only.

Remaining follow-up:

- Continue auditing DER/TLV parsing boundaries for places where unknown optional data should remain compatible but malformed required structure should fail closed.

### 2026-06-21 Chip Authentication Metadata Conflict Pass

Completed:

- Continued the security-metadata audit after tightening top-level `SecurityInfo` parsing, focusing on DG14 Chip Authentication selection.
- Found that duplicate `ChipAuthenticationInfo` entries with the same effective key ID silently overwrote earlier metadata. Because the existing CA key-id normalization maps an absent key ID and explicit key ID `0` into the same default slot, conflicting DG14 metadata could change which CA OID was used without any failure.
- Added `ChipAuthenticationHandler.metadata(from:)` as the single normalization point for CA metadata. It preserves compatible duplicate entries only when OID, version, and key-id presence all match exactly, and rejects conflicting duplicates with `InvalidASN1Structure`.
- Made the DG14-backed `ChipAuthenticationHandler` initializer throwing so malformed/conflicting CA metadata fails closed before CA command construction.
- Updated `PassportReader` so metadata-normalization failure marks Chip Authentication failed and emits the existing privacy-safe CA failure event/progress without re-establishing BAC. BAC is still re-established after an actual CA attempt fails, where a command may already have reached the chip and secure-messaging state may need rebuilding.
- Added focused tests for exact duplicate CA metadata, conflicting duplicate metadata for the same key ID, and absent-vs-zero key-id slot conflicts.
- No public API or README migration update was needed; the behavior change is internal fail-closed handling for malformed chip-controlled DG14 metadata.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 67 core tests passed, including the new Chip Authentication metadata regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 205 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched CA handler and reader sources found no new raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were existing typed redacted `eventLogger.log(...)` calls, APDU/key terminology, plan privacy wording, and pre-existing synthetic secure-messaging/core test vectors.

Remaining follow-up:

- Continue auditing Chip Authentication public-key selection and retry behavior for chips with multiple public keys, especially cases where one failed attempt may leave secure messaging unusable before later public keys are tried.

### 2026-06-21 Chip Authentication Retry State Pass

Completed:

- Continued the Chip Authentication state-machine audit after the DG14 metadata conflict pass.
- Found that `ChipAuthenticationHandler.doChipAuthentication()` swallowed every thrown per-public-key attempt failure and tried the next public key. That is unsafe after an NFC CA command may have reached the chip, because secure-messaging state may be changed or desynchronized before the next attempted key.
- Changed the CA retry contract so `false` attempt results still allow trying the next public key for local unsupported/non-selected-key cases, but thrown attempt failures now stop the loop immediately and propagate to the reader's existing CA failure recovery path.
- Added an internal main-actor attempt-injection helper for direct state-machine testing without a fake NFC tag or real OpenSSL key material.
- Added focused tests proving unsupported public keys can still be skipped, while thrown CA attempt failures do not touch later public keys.
- The first focused build caught a Swift 6 actor-isolation issue in the injected attempt closure. The closure is now explicitly `@MainActor`, preserving the handler's actor boundary instead of weakening concurrency checks.
- No public API or README migration update was needed; this is internal retry behavior and failure recovery hardening.

Verification:

- Initial focused core-test build failed with Swift's `sending 'pubKey' risks causing data races` diagnostic for the new injected attempt closure. The closure was made `@MainActor`, then verification was rerun successfully.
- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 69 core tests passed, including the new Chip Authentication retry-state regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 207 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched CA handler source and focused core tests found no new raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink in production. Remaining changed-file hits were expected planning-document privacy wording, APDU/key terminology, and pre-existing synthetic secure-messaging/core test vectors.

Remaining follow-up:

- Continue auditing CA/PACE fallback boundaries for places where recovery should distinguish local pre-transmission failures from errors after a protected command may have reached the chip.

### 2026-06-21 PACE Single-Attempt Recovery Pass

Completed:

- Continued the CA/PACE fallback-boundary audit after tightening Chip Authentication retry behavior.
- Found the same unsafe recovery shape in PACE: `PassportReader.startReading(tagReader:)` built an ordered list of advertised PACEInfos, swallowed each thrown PACE attempt, and tried the next one. Because `PACEHandler.doPACE(...)` sends MSE Set AT and General Authenticate commands early in the attempt, a thrown failure may leave the chip/session state changed before the next PACEInfo is attempted.
- Replaced the multi-attempt PACE loop with a single attempt against `CardAccess.preferredPACEInfo`, preserving the existing selection rule of first implemented PACEInfo, or first advertised PACEInfo if none are implemented so local preflight can fail normally.
- Added synthetic EF.CardAccess tests proving `preferredPACEInfo` selects the first implemented entry and falls back to the first advertised entry when none are implemented.
- No public API or README migration update was needed; this is internal recovery behavior hardening.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 69 diagnostics tests passed, including the new CardAccess/PACE selection regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 209 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched reader source and diagnostics tests found no new raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink in production. Remaining changed-file hits were existing typed redacted `eventLogger.log(...)` calls, planning-document privacy wording, APDU/key terminology, and synthetic privacy/crypto test fixtures.

Remaining follow-up:

- Continue auditing authentication fallback after PACE and CA failures, especially whether BAC fallback should be skipped or made explicit under strict PACE policies when a PACE command reached the chip but did not complete.

### 2026-06-21 Strict PACE Policy Gate Coverage Pass

Completed:

- Continued the PACE fallback-boundary audit after replacing multi-attempt PACE recovery with a single selected PACEInfo attempt.
- Verified the existing strict PACE policy logic already fails closed for `.requirePACEWhenAdvertised` and `.requireExplicitCredential` instead of allowing BAC fallback after PACE failure.
- Added focused regression tests proving strict PACE policies do not fall back to BAC after PACE failure, strict PACE policies reject `skipPACE` before a session starts, and `.requireExplicitCredential` requires matching explicit credential state at both the pre-session and pre-attempt gates.
- Added an internal DEBUG-only test configurator for PACE policy and credential state. It is not public API and only exists in debug/test builds.
- No public API, README, or migration update was needed because this pass preserves existing behavior and locks the expected fail-closed policy semantics with tests.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 72 diagnostics tests passed, including the new strict PACE policy gate regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 212 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched reader source, diagnostics tests, and planning document found no new raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink in production. Remaining changed-file hits were existing typed redacted `eventLogger.log(...)` calls, planning-document privacy wording, APDU/key terminology, and synthetic privacy/crypto test fixtures.

Remaining follow-up:

- Continue auditing fallback/error classification, especially if future work needs distinguishing pre-transmission local PACE failures from post-command failures under `.allowBACFallback`.

### 2026-06-21 Strict Decrypted Padding Pass

Completed:

- Continued the cryptographic-boundary audit from the Secure Messaging and PACE-CAM receive/decrypt side.
- Found that the shared `unpad(...)` helper intentionally returned the original input when no ISO padding marker was present. That lenient behavior is useful for compatibility at generic utility call sites, but it let security-sensitive decrypted payload paths accept malformed padded plaintext after a valid checksum/decryption step.
- Added `strictUnpad(...)` for ISO 9797-1 method 2 padding validation. It rejects empty input and decrypted payloads that do not contain the required `0x80` padding marker before trailing zeroes.
- Changed `SecureMessaging.unprotect(rapdu:)` to reject authenticated protected responses whose decrypted DO'87 payload has malformed padding instead of returning the decrypted bytes as a successful payload.
- Changed `PACEChipAuthenticationMappingResult` to reject decrypted CAM data with malformed padding before retaining chip-authentication data for public-key verification.
- Added focused tests for strict padding validation, authenticated Secure Messaging responses with malformed decrypted padding, and malformed encrypted PACE-CAM data.
- No public API, README, or migration update was needed; this is internal fail-closed parsing hardening for decrypted chip-controlled payloads.

Verification:

- Focused iOS Simulator core and diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 143 selected tests passed, including the new strict padding, Secure Messaging, and PACE-CAM regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 214 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched Secure Messaging, PACE-CAM, utility, core-test, diagnostics-test, and planning files found no new raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink in production. Remaining changed-file hits were internal APDU/key terminology, planning-document privacy wording, redacted event references, and synthetic crypto/privacy test fixtures.

Remaining follow-up:

- Continue auditing decrypted cryptographic boundaries for any other lenient parse helpers that should fail closed when operating on authenticated or decrypted chip-controlled data.

### 2026-06-21 BAC Mutual Authentication Response Verification Pass

Completed:

- Continued the authentication-boundary audit from BAC mutual-authentication response handling.
- Found that `BACHandler.sessionKeys(data:)` accepted any response with at least 32 bytes, decrypted the first 32 bytes, ignored the trailing response MAC, and did not verify that the chip echoed the expected ICC and terminal nonces before deriving session keys.
- Tightened BAC session-key derivation so the mutual-authentication response must be exactly 40 bytes, the 8-byte response MAC must verify over the encrypted response in constant time, the decrypted payload must be exactly 32 bytes, and the decrypted ICC/terminal nonce echoes must match the active BAC attempt before session keys are derived.
- Updated the BAC session-key doc comment so it no longer claims a fixed 16-byte key size for the expanded secure-messaging keys used by this implementation.
- Added focused synthetic BAC tests that build a valid mutual-authentication response from in-memory test state, verify successful session-key derivation, and reject tampered MACs, trailing bytes, and mismatched nonce echoes.
- No public API, README, or migration update was needed; this is internal authentication-response verification hardening.

Verification:

- Initial focused core test run failed because the new test expected 16-byte session keys, but this BAC/DESede implementation derives expanded 24-byte keys. The test expectation was corrected and verification was rerun successfully.
- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 72 core tests passed, including the new BAC mutual-authentication response verification regressions.
- Release verification passed after the final code-note and exact-length cleanup:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 215 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over the touched BAC source returned no matches for raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sinks. The changed-file sensitive-pattern scan found expected internal BAC/APDU/key terminology, planning-document privacy wording, and synthetic secure-messaging/core test fixtures only.

Remaining follow-up:

- Continue auditing authentication response validation and state cleanup, especially PACE/BAC/CA boundaries where authenticated response bytes, nonce echoes, or retry state affect later secure messaging.

### 2026-06-21 Session Key Seed Validation Pass

Completed:

- Continued the session-key and crypto-derivation boundary audit after hardening BAC mutual-authentication response verification.
- Found that the shared `SecureMessagingSessionKeyGenerator` would derive keys from an empty key seed instead of failing locally. Because this generator is used by BAC, PACE, and Chip Authentication key derivation paths, empty upstream material should be treated as invalid input before any digest or key extraction work.
- Added a fail-closed guard in the shared derivation entry point so empty key seeds throw `InvalidDataPassed("Missing key seed")` before hashing. The thrown error remains privacy-safe through the existing `localizedDescription` and `description` mappings.
- Added focused tests proving empty key seeds are rejected without surfacing sensitive key labels or byte-like fragments, and proving valid DESede/AES-128/AES-192/AES-256 derivations still return the expected implementation key lengths.
- No public API, README, or migration update was needed; this is internal crypto-boundary hardening.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 74 core tests passed, including the new session-key seed validation regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 217 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, or redacted diagnostic events.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over the touched session-key generator returned no matches for raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sinks. The changed-file sensitive-pattern scan found expected planning-document privacy wording, APDU/key terminology, and synthetic secure-messaging/core test fixtures only.

Remaining follow-up:

- Continue auditing direct PACE credential validation, cipher/digest naming drift, and any remaining authentication-state transitions where empty, malformed, or unsupported cryptographic material could advance past local validation.

### 2026-06-21 PACE Credential And Cipher Normalization Pass

Completed:

- Continued the PACE credential and session-key derivation audit after adding the shared empty-key-seed guard.
- Found that direct PACE key derivation could still accept an empty or whitespace-only access credential because it hashes the credential string before calling the shared session-key generator. SHA-1 of empty input is non-empty, so the prior key-seed guard could not catch this path.
- Added a PACE key-creation guard that rejects empty or whitespace-only credentials before hashing, with a privacy-safe `PACEError("Key derivation", "Missing PACE credential")`.
- Extracted PACE key creation into a testable internal static helper while preserving the existing instance method used by the scan flow.
- Found and fixed cipher-name drift in `SecureMessagingSessionKeyGenerator`: key extraction already accepted lowercase/`hasPrefix("aes")` names, but digest selection remained case-sensitive and rejected equivalent supported names such as `aes-128`.
- Normalized supported cipher names consistently for DESede/3DES and AES/AES-128/AES-192/AES-256 derivation paths.
- Added focused tests proving missing PACE credentials fail before hashing, valid CAN/MRZ credentials still derive expected key lengths, and supported lowercase/alias cipher names derive expected DESede/AES key lengths.
- No public API, README, or migration update was needed; this is internal PACE/session-key boundary hardening.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 77 core tests passed, including the new PACE credential and cipher-normalization regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 220 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, or redacted diagnostic events.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over the touched PACE and session-key generator sources returned no matches for raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sinks. The changed-file sensitive-pattern scan found expected planning-document privacy wording, internal PACE constants, APDU/key terminology, and synthetic secure-messaging/core test fixtures only.

Remaining follow-up:

- Continue auditing PACE response parsing and state cleanup, especially nonce length expectations, authentication-token shape, and whether failed PACE attempts can leave mapping state that affects later fallback behavior.

### 2026-06-21 PACE Response Shape Validation Pass

Completed:

- Continued the PACE response parsing and failed-state cleanup audit after credential and cipher-normalization hardening.
- Found that PACE Step 1 only checked for a non-empty decrypted nonce. A malformed or oversized encrypted nonce could be accepted by the PACE handler and, for GM/CAM, flow into BIGNUM mapping instead of failing at the chip-response boundary.
- Added explicit PACE nonce length validation before and after decrypting the Step 1 nonce. DESede and AES-128 expect 16 bytes; AES-192 and AES-256 expect 32 bytes. Unsupported cipher/key combinations now fail with `UnsupportedCipherAlgorithm` before nonce processing.
- Reused the same expected nonce-length helper for Integrated Mapping input sizing so Step 1 and IM stay aligned.
- Found that the Step 4 authentication-token parser accepted any present `0x86` value and relied on later constant-time comparison to reject wrong lengths. Tightened the parser so malformed tokens fail at parse time unless they are exactly 8 bytes.
- Updated focused tests so the valid PACE token fixture uses an 8-byte token, wrong-length tokens are rejected with a typed privacy-safe PACE error, and nonce length expectations are pinned for DESede/AES-128/AES-192/AES-256 plus unsupported inputs.
- No public API, README, or migration update was needed; this is internal chip-response validation hardening.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 79 core tests passed, including the new PACE response-shape regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 222 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, or redacted diagnostic events.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over the touched PACE source returned no matches for raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sinks. The changed-file sensitive-pattern scan found expected planning-document privacy wording, internal PACE constants, APDU/key terminology, and synthetic secure-messaging/core test fixtures only.

Remaining follow-up:

- Continue auditing PACE and Chip Authentication state cleanup around failed attempts, especially CAM mapping state, secure-messaging restart boundaries, and fallback behavior after partially completed authentication flows.

### 2026-06-21 Authentication State Cleanup Pass

Completed:

- Continued the PACE/CAM and Chip Authentication failed-state cleanup audit after tightening PACE response parsing.
- Found that `PACEHandler.doPACE(...)` preserved the CAM mapping result during deferred cleanup even if a later finalization step threw. It now keeps the mapping result only after PACE has fully completed; failed or partial attempts clear it with the rest of the transient PACE state.
- Made `PassportReader` retain the active `PACEHandler` only for the duration of the PACE attempt and explicitly scrub it afterward. This gives cancellation/failure cleanup a concrete active handler while avoiding stale PACE state after success or fallback.
- Tightened trusted CardSecurity CAM handling so a CAM result is cleared once it has been checked against trusted CardSecurity keys, whether it verifies or fails. Verified CAM still marks Chip Authentication successful; failed CAM now records `.failed` instead of keeping stale mapping material for later.
- Made Chip Authentication fallback cleanup explicit: failed CA attempts and post-CA data-group retry fallback now call `removeSensitiveData()` before dropping the handler and re-establishing BAC, instead of relying on deinitialization side effects.
- Added a focused cleanup regression proving `ChipAuthenticationHandler.removeSensitiveData()` clears queued General Authenticate segments, CA metadata, public key metadata, and the support flag.
- No public API, README, or migration update was needed; this is internal authentication-state lifetime hardening.

Verification:

- Focused iOS Simulator core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 80 core tests passed, including the new Chip Authentication cleanup regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 223 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, or redacted diagnostic events.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow production sink scan over the touched PACE/reader sources and focused core tests found no new raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink in production. Remaining changed-file hits were expected typed redacted `eventLogger.log(...)` calls, internal PACE constants, APDU/key terminology, and synthetic secure-messaging/core test fixtures only.

Remaining follow-up:

- Continue broader state-lifetime passes around Active Authentication challenge/signature handling, verification ordering after failed optional authentication, and any places where an internal handler can keep a tag or secure-messaging object longer than the scan step requires.

### 2026-06-21 Active Authentication Input Validation Pass

Completed:

- Continued the state-lifetime and verification-state audit from the Active Authentication angle.
- Found that caller-supplied Active Authentication challenges could be any length, and `NFCPassportModel.verifyActiveAuthentication(...)` recorded challenge/signature bytes before validating their shape. That made it possible for malformed AA inputs to be retained in the model even though they could not be valid verification material.
- Added AA input validation in the model: challenges must be exactly 8 bytes, signatures must be non-empty, and signatures must be no larger than 64 KiB before the model stores them or calls RSA/ECDSA verification helpers.
- Added an `activeAuthenticationAttempted` state bit so the model can distinguish "attempted but failed" from "not checked" without relying on retained challenge/signature bytes. Privacy cleanup resets this flag along with the retained bytes.
- Added an NFC transport guard in `TagReader.doInternalAuthentication(...)` so invalid custom AA challenges are rejected before Internal Authenticate APDU construction or NFC transmission.
- Updated existing cleanup fixtures to use valid-shaped synthetic AA challenges, and added a focused regression proving malformed AA inputs do not retain challenge/signature bytes and that the AA input validator accepts only the reviewed shape.
- No README or app migration update was needed; this is internal validation and retention hardening. The behavior change is fail-closed for malformed custom AA challenges.

Verification:

- Focused iOS Simulator diagnostics/core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 153 selected tests passed, including the new malformed AA input retention regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 224 tests with no failures. Risky-pattern output remained expected documentation, migration-note, synthetic-test, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, or redacted diagnostic events.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model/NFC/diagnostics-test files and this plan found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected typed logger tests, planning-document privacy wording, internal APDU/AA challenge/signature terminology, and synthetic privacy/crypto test fixtures.

Remaining follow-up:

- Continue auditing verification ordering and optional-authentication status semantics, especially places where "attempted but failed" and "not supported/not requested" can be confused after malformed or skipped inputs.

### 2026-06-21 Active Authentication Preflight Validation Pass

Completed:

- Continued the Active Authentication boundary audit after adding model-level AA input validation.
- Found that malformed caller-supplied custom AA challenges were rejected at the NFC Internal Authenticate command boundary, but only after `PassportReader` had accepted the value and configured scan state.
- Added reader preflight validation before `beginScanIfPossible()` so malformed custom AA challenges fail closed before an NFC scan starts. The preflight path also clears any pending PACE credential before throwing.
- Shared the exact 8-byte AA challenge validator between the model, reader preflight, and `TagReader.doInternalAuthentication(...)` so future changes have one reviewed shape rule.
- Updated the README to document that custom Active Authentication challenges must be exactly 8 bytes and are rejected before scan start when malformed.
- Added a focused reader regression covering nil, valid, empty, short, and long custom AA challenge inputs.

Verification:

- Focused iOS Simulator diagnostics/core tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests -only-testing:NFCPassportReaderTests/NFCPassportReaderTests
  ```

  Result: 154 selected tests passed, including the new reader preflight AA challenge regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 225 tests with no failures. Risky-pattern output remained expected documentation, migration-note, synthetic-test, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, or redacted diagnostic events.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model/NFC/reader/diagnostics-test/docs files found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected typed logger tests, redacted reader events, planning-document/README privacy wording, internal APDU/AA challenge/signature terminology, and synthetic privacy/crypto test fixtures.

Remaining follow-up:

- Continue auditing optional-authentication status semantics and verification ordering, especially where fail-closed preflight errors, unsupported chip features, and "not requested" states can be confused.

### 2026-06-21 Optional Authentication Status Precedence Pass

Completed:

- Continued the optional-authentication verification-status audit after AA preflight validation.
- Found that DG14/DG15 unsupported reads were recorded as both `.failed` and `.unsupported`, but the verification detail checked `.failed` before `.unsupported`. That could report an unsupported optional-authentication data group as "skipped," which is misleading for safe diagnostics and policy review.
- Tightened Active Authentication and Chip Authentication detail precedence: explicit profile/policy skips still report `.skipped`, unsupported reads report `.notSupported`, and real DG14/DG15 read failures now report `.failed` with `.attemptedFailed`.
- Added focused diagnostics tests for failed DG14/DG15 reads and for unsupported reads that follow a transient failed read status.
- No README or migration update was needed; the public shape is unchanged, and the behavior is a more accurate fail-closed diagnostic for existing safe verification fields.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 76 diagnostics tests passed, including the new optional-authentication status precedence regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 227 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model, diagnostics-test, and planning files found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected typed logger tests, planning-document privacy wording, internal AA/signature terminology, and synthetic privacy/crypto fixtures.

Remaining follow-up:

- Continue auditing optional-authentication and passive-verification interactions where status details can affect app-side trust decisions, especially after partial reads or recovery paths.

### 2026-06-21 Reader Progress Callback Lifetime Pass

Completed:

- Continued the reader lifecycle and recovery-path audit after tightening optional-authentication status reporting.
- Found that the NFC tag-reader progress callback captured `PassportReader` as `unowned self`. Because scans can be cancelled or timed out while asynchronous NFC work and progress callbacks are still in flight, a late progress callback could trap if the reader had already been released.
- Extracted progress rendering into `makeTagReaderProgressHandler()` and changed the callback to capture the reader weakly. Late callbacks now no-op instead of crashing, while preserving progress throttling, clamping, and redacted progress events during an active scan.
- Added a focused non-NFC lifecycle regression proving the progress handler does not retain the reader and can be invoked after reader release without trapping.
- No README or migration update was needed; this is an internal predictability/lifetime hardening change with no public API shape change.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 77 diagnostics tests passed, including the new progress-handler lifetime regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 228 tests with no failures. Risky-pattern output remained expected documentation, synthetic-test, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched reader, diagnostics-test, and planning files found no remaining `unowned self` in the touched reader path and no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected typed redacted reader events, planning-document privacy wording, internal APDU/AA terminology, and synthetic privacy/crypto fixtures.

Remaining follow-up:

- Continue auditing async NFC session tasks and cancellation/recovery boundaries for stale state updates after a scan has already completed or failed.

### 2026-06-21 Reader Scan Generation Guard Pass

Completed:

- Continued the async NFC lifecycle audit after replacing the progress callback's `unowned` capture.
- Found that old NFC delegate tasks, timeout tasks, cancellation handlers, and progress callbacks all targeted shared reader state. After a cancellation, timeout, or failure, a stale task could theoretically complete later and invalidate, fail, clear, or emit progress for a newer scan on the same `PassportReader` instance.
- Added an internal monotonically increasing scan ID. Each accepted scan captures its ID, and continuation storage, timeout failure, cancellation, delegate invalidation, tag-detection work, success completion, failure invalidation, and progress callbacks now no-op unless their ID still matches the active scan.
- Guarded direct success-session invalidation inside `startReading(...)` with the same scan ID so stale read work cannot invalidate a newer session.
- Split matched-scan cleanup from continuation presence. A cancellation that happens before continuation storage can still scrub scan state, while a stale scan ID remains a true no-op.
- Added focused non-NFC regression coverage proving a stale scan failure does not clear the active scan state.
- No README or migration update was needed; this is internal concurrency/lifecycle hardening with no public API shape change.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 78 diagnostics tests passed, including the new stale scan generation regression. An initial attempt using unavailable simulator `iPhone 16` failed before build/test because that simulator is not installed in this Xcode environment; the run was repeated against the available `iPhone 17` iOS 26.5 simulator.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 229 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

Remaining follow-up:

- Continue auditing async reader state for remaining cross-scan coupling, especially display-message state, tracking delegate callbacks, and long-running authentication/data-group reads under cancellation.

### 2026-06-21 Reader Phase Stale-State Checkpoint Pass

Completed:

- Continued the reader async lifecycle audit after adding scan-generation guards for final completion/failure/progress paths.
- Found a remaining cross-scan risk inside long-running read phases: stale NFC/authentication/data-group tasks could resume after cancellation or failure and mutate shared reader state before final completion, including `passport`, authentication handlers, data-group read statuses, progress events, display messages, and tracking delegate callbacks.
- Added a shared `ensureActiveScan(_:)` checkpoint and threaded scan IDs through PACE, BAC, Chip Authentication, Active Authentication, data-group selection, data-group parsing, and verification phase boundaries.
- Added liveness checks immediately after NFC/authentication awaits and before shared-state writes, so stale read work now fails closed with `.UserCanceled` instead of mutating a newer scan's model or emitting stale phase callbacks.
- Added the same checkpoint after optional Card Security reads in the PACE path, including the `nil` result path where `try?` intentionally suppresses card-security read errors for compatibility.
- Preserved active-scan behavior and existing fallback/retry semantics: PACE-to-BAC fallback, CA fallback, data-group retry, unsupported-data-group handling, and verification still proceed when the scan ID remains current.
- Added focused non-NFC regression coverage proving stale phase checkpoints fail closed once the scan has ended.
- No README or migration update was needed; this is internal concurrency/lifecycle hardening with no public API shape change.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 79 diagnostics tests passed, including the new stale phase checkpoint regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 230 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched reader, diagnostics-test, and planning files found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected typed redacted reader events, planning-document privacy wording, APDU/key terminology, and synthetic privacy/crypto fixtures.

Remaining follow-up:

- Continue auditing reader lifecycle behavior for duplicate progress/log events and for any remaining shared state that should be reset or snapshotted per scan.

### 2026-06-21 DG2 ISO Record Length Boundary Pass

Completed:

- Continued parser hardening from the chip-controlled length and retained-sensitive-image-data angle.
- Found that the DG2 ISO/IEC 19794-5 single facial-record path read `facialRecordDataLength` but then parsed against the full remaining payload. A malformed record with a declared face-record length that was too short or too long could therefore be accepted, and trailing undeclared bytes could be treated as image data.
- Tightened the single-record parser so `facialRecordDataLength` must cover exactly the remaining single-record payload and the parser uses that declared boundary as `recordEnd`.
- Found the adjacent top-level `lengthOfRecord` was also parsed but not enforced. A malformed ISO face record could therefore advertise a shorter or longer top-level payload than the bytes actually supplied.
- Tightened the parser so top-level `lengthOfRecord` must match the ISO payload length before any facial records are retained.
- Updated older synthetic DG2 parser fixtures that were only accepted because the parser ignored declared ISO/facial-record boundaries. The fixtures now use the shared structural DG2 helper with matching lengths, and the missing-image negative fixture now has a consistent top-level length so it reaches the intended image-format assertion.
- Added focused regression coverage for short and long declared facial-record lengths and top-level record lengths, including assertions that previously retained image bytes are not replaced on malformed input.
- No README or migration update was needed; this is internal malformed-chip parser hardening with no public API shape change.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 75 parser tests passed after the top-level length guard. Earlier focused runs exposed inconsistent synthetic DG2 fixtures with bad declared facial-record or top-level record lengths; those fixtures were corrected rather than weakening production validation.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 234 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched DG2 parser, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing remaining chip-controlled length fields across data-group parsers, especially nested optional data lengths outside DG2.

### 2026-06-21 DG11/DG12 Tag List Enforcement Pass

Completed:

- Continued parser hardening from the optional data-group declaration and retained-sensitive-fields angle.
- Found that DG11 and DG12 read the `5C` tag list but skipped enforcement. A malformed chip payload could include recognized optional fields that were not declared in the tag list, and the parser would still decode and retain them.
- Added shared tag-list parsing for the one- and two-byte tags used by LDS data-group parsers.
- Tightened DG11 and DG12 so recognized optional fields must appear in the declared `5C` tag list before they are decoded or retained.
- Preserved existing compatibility for data groups that end immediately after an incomplete tag-list marker; absent fields after the tag list still parse as empty optional data.
- Added focused regression coverage proving undeclared DG11 text fields and undeclared DG12 image fields are rejected before retention.
- No README or migration update was needed; this is internal malformed-chip parser hardening with no public API shape change.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 77 parser tests passed, including the new undeclared-field regressions and the existing absent-fields-after-tag-list compatibility tests.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 236 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched base data-group parser, DG11/DG12 parsers, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing remaining chip-controlled declaration lists and nested optional data lengths outside DG11/DG12.

### 2026-06-21 COM Data Group List Validation Pass

Completed:

- Continued parser hardening from the chip-controlled declaration-list angle.
- Found that COM `5C` data-group list parsing silently ignored unknown tag bytes and preserved duplicate advertised groups.
- Changed COM parsing to fail closed with `InvalidASN1Structure` when the chip advertises an unknown data-group tag byte, rather than dropping it and continuing with a partial declaration.
- Changed COM parsing to deduplicate repeated advertised data groups while preserving first-seen order, keeping downstream read selection and status reporting stable.
- Added focused regression coverage for unknown COM data-group tags and duplicate COM-advertised groups using synthetic TLV fixtures.
- No README or migration update was needed; this is internal malformed-chip parser hardening with no public API shape change.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 79 parser tests passed, including the new COM malformed-tag and deduplication regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 238 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched COM parser, parser lookup file, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing remaining chip-controlled declaration lists and nested optional data lengths outside COM, DG11, DG12, and DG2.

### 2026-06-21 SOD Hash Entry Validation Pass

Completed:

- Continued passive-authentication hardening from the malformed SOD declaration angle.
- Found that structured SOD data-group hash parsing accepted duplicate data-group hash entries by silently overwriting the earlier value in a dictionary.
- Found that SOD hash octet strings were accepted without checking that their byte length matched the selected digest algorithm.
- Tightened SOD hash parsing so each hash entry must be a sequence, data-group numbers must be unique, and hash byte counts must match the digest algorithm before the hash map is returned to verification.
- Added focused synthetic SOD parser regressions for duplicate data-group hashes and SHA-256 hash length mismatch.
- No README or migration update was needed; this is internal malformed-SOD parser hardening with no public API shape change.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 81 parser tests passed, including the new duplicate-hash and hash-length regressions.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 240 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model parser, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing passive-authentication edge cases, especially SOD coverage semantics and malformed CMS structures that should fail closed without exposing certificate or hash material.

### 2026-06-21 SOD Coverage Semantics Pass

Completed:

- Continued passive-authentication hardening from the verification coverage angle.
- Found that `PassportVerificationResult.dataGroupCoverage` exposed a `coveredButNotRead` status, but the model only remembered SOD hashes for data groups that were actually read and compared. As a result, a minimal scan could not report SOD-listed groups that were not read, even though the public coverage enum promised that distinction.
- Added safe internal tracking of SOD-listed data-group IDs during passive verification without retaining additional raw hash values for unread groups.
- Updated coverage generation to use the SOD-listed ID set plus read data groups, so read/matched groups, read-but-uncovered groups, and covered-but-unread groups are all reported truthfully.
- Cleared the SOD-listed ID set during repeated verification attempts and privacy cleanup to avoid stale coverage in reused models.
- Added a focused synthetic SOD regression proving a DG1-only read with SOD hashes for DG1 and unread DG2 reports DG1 as `coveredAndMatched` and DG2 as `coveredButNotRead`.
- No README or migration update was needed; this makes an existing public coverage state accurate without changing API shape.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 82 parser tests passed, including the new SOD covered-but-unread coverage regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 241 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing passive-authentication and verification-result semantics for places where a status can be technically true but too broad for the evidence gathered by a minimal scan.

### 2026-06-21 Data Group Coverage Ordering Pass

Completed:

- Continued the verification-result predictability audit from the coverage semantics pass.
- Found that `PassportVerificationResult.dataGroupCoverage` was sorted by LDS EF tag byte values, which can put later logical data groups such as DG11 before DG2.
- Added a private logical data-group-number ordering for coverage output, keeping COM, SOD, and unknown IDs outside normal document data-group ordering.
- Extended the synthetic SOD coverage regression so SOD entries are deliberately encoded out of logical order and include unread DG11 plus unread DG2; the public result now asserts DG1, DG2, DG11 ordering.
- No README or migration update was needed; the API shape and statuses are unchanged, and the result order is now more predictable for app display and diagnostics.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 82 parser tests passed, including the data-group coverage ordering regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 241 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing verification-result semantics and policy decisions for minimal scans.

### 2026-06-21 SOD-Only Hash Verification Pass

Completed:

- Continued the passive-authentication semantics audit from the coverage work.
- Found that a model containing only COM/SOD, or only SOD, could mark `passportDataNotTampered` and `PassportVerificationResult.dataGroupHashStatus` as passed even though no non-COM/SOD data group hash had actually been compared.
- Added an internal `PassiveAuthenticationError.NoDataGroupHashesCompared` condition and require at least one read document data group to be compared before data-group hash verification can pass.
- Kept the public verification API shape stable by mapping this edge case to the existing safe failed `attemptedFailed` detail reason rather than exposing raw hash or SOD detail.
- Added a synthetic SOD-only regression proving unread SOD-listed data groups are reported as `coveredButNotRead`, no computed hashes are retained, and data-group hash verification does not pass without a read group comparison.
- No README or migration update was needed; this narrows an overconfident pass state without changing public API names or required app calls.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 83 parser tests passed, including the new SOD-only no-compared-hashes regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 242 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched error/model source, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected APDU error type names, planning-document privacy wording, and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing verification-result semantics and policy decisions for minimal scans.

### 2026-06-21 Privacy Cleanup State Reset Pass

Completed:

- Audited model reuse and post-cleanup state from the stale-state angle.
- Found that `NFCPassportModel.removeSensitiveDataForPrivacy()` cleared raw data groups, hashes, certificates, and Active Authentication byte arrays, but could leave verification flags, verification errors, signer/master-list metadata, chip-authentication state, and Active Authentication pass state behind.
- Updated cleanup to reset verification/authentication booleans, accumulated verification errors, signer/master-list metadata, revocation status, and chip-authentication status along with raw material.
- Extended the model cleanup regression so a model that had raw data, retained AA bytes, and attempted verification returns to a neutral `notChecked` verification result after cleanup instead of surfacing stale missing-SOD or previous-authentication state.
- No README or migration update was needed; this tightens internal data minimization and makes the existing cleanup behavior safer without changing public API shape.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 79 diagnostics tests passed, including the strengthened cleanup state-reset regression.
- Release verification passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 242 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model source, diagnostics tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected logger/privacy negative tests and planning-document privacy wording.

Remaining follow-up:

- Continue auditing stale state after scan cancellation/failure and repeated model reuse.

### 2026-06-21 Data Group Hash Helper Consistency Pass

Completed:

- Audited passive-authentication-adjacent helper code for inconsistent hash semantics.
- Found that the legacy `NFCPassportModel.getHashesForDatagroups(...)` helper hashed only the data-group body, while passive authentication and `DataGroup.hash(...)` correctly hash the full encoded data group bytes.
- Updated the helper to delegate to `DataGroup.hash(...)`, ensuring any future internal call site computes the same value used for SOD data-group hash comparison.
- Added a focused regression proving the helper hashes the retained full encoded data group, does not match body-only hashing, and ignores unsupported hash algorithm names rather than returning misleading values.
- No README or migration update was needed; the helper is internal and this preserves the existing API surface while removing an unsafe future footgun.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests
  ```

  Result: 84 parser tests passed, including the data-group hash helper regression.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model source, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing dormant internal helpers for behavior that would be unsafe if reused.

### 2026-06-21 Mutable Model State Invalidation Pass

Completed:

- Audited the mutable `NFCPassportModel` state machine for stale derived authentication/verification results after raw data-group changes.
- Found that `addDataGroup(...)` could replace or add data groups after passive verification while leaving prior `passportVerificationAttempted`, hash-comparison results, certificate state, and verification errors intact. That could make a reused model report a stale successful verification for a different data-group set.
- Updated `addDataGroup(...)` to clear derived passive-verification state on any data-group mutation, including SOD hash coverage, parsed hash results, certificate trust objects, master-list metadata, and verification errors.
- Updated `addDataGroup(...)` to clear Active Authentication challenge/signature/result state when DG14 or DG15 changes, and to reset Chip Authentication status when DG14 changes.
- Added focused regressions proving data mutation after a successful hash comparison returns passive verification to `notChecked`, and that DG14/DG15 mutations clear derived Active/Chip Authentication state and retained AA bytes.
- No README or migration update was needed; this is internal mutable-model hygiene and preserves the public API while making repeated/internal model use safer and more predictable.

Verification:

- Focused iOS Simulator parser and diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 165 selected tests passed, including the stale passive-verification and authentication-state mutation regressions.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 245 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model, parser tests, diagnostics tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected logger/redaction negative tests, synthetic parser fixtures, planning-document privacy wording, and MRZ/APDU/key scanner patterns.

Remaining follow-up:

- Continue auditing mutable reader/model state around cancellation, retry, and optional authentication paths.

### 2026-06-21 Reader Invalidation Suppression State Pass

Completed:

- Continued the reader cancellation/retry state audit, focusing on scan-local state that can survive across CoreNFC delegate callbacks.
- Found that `shouldNotReportNextReaderSessionInvalidationErrorUserCanceled` could remain set after a successful read or deliberate invalidation because the reader clears `readerSession` before CoreNFC's later invalidation callback can consume the flag. A later scan using the same `PassportReader` instance could then swallow a real NFC-sheet user cancellation and leave the active continuation unresolved.
- Made the user-cancel invalidation suppression flag scan-scoped by clearing it when a new scan begins and whenever active scan state is consumed by success or failure.
- Guarded `tagReaderSessionDidBecomeActive(...)` with the current session/scan check so stale activation callbacks cannot emit session-start logs for an old session after a newer scan begins.
- Added a focused non-NFC regression proving the suppression flag is cleared at scan start, failure teardown, and success teardown.
- No README or migration update was needed; this tightens internal reader lifecycle behavior without changing public API shape or app integration code.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests
  ```

  Result: 81 diagnostics tests passed, including the new cross-scan invalidation-suppression regression.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 246 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched reader source, diagnostics tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected typed redacted `eventLogger.log(...)` calls, logger/redaction negative tests, synthetic sensitive-pattern fixtures, and planning-document privacy wording.

Remaining follow-up:

- Continue auditing reader lifecycle state around display-message handlers, progress rendering, and explicit cancellation races.

### 2026-06-21 Result Diagnostics Photo Policy Consistency Pass

Completed:

- Audited app-facing result and diagnostics projections for mismatches between safe returned data and safe metadata.
- Found that `PassportChipReadResult(passport:photoPolicy:)` correctly omitted `faceImageData` when the effective photo policy was `.skip`, but its nested `diagnosticsSummary` was created through `PassportReaderDiagnosticsSummary(passport:)`, which inferred `.read` whenever DG2 was present on the model. A caller could therefore receive no photo bytes while diagnostics reported the photo policy as `.read`.
- Updated `PassportChipReadResult` to build its diagnostics summary with the same effective `photoPolicy` used to decide whether face-image bytes are returned.
- Added a focused regression with a tiny synthetic DG2 payload proving `.skip` omits `faceImageData` and reports `.skip`, while `.read` returns the image wrapper and reports `.read`.
- No README or migration update was needed; this preserves the public API and corrects privacy-safe metadata to match existing documented policy behavior.

Verification:

- An initial focused diagnostics test command targeted an unavailable `iPhone 16` simulator and failed before compiling. The command was rerun on an installed `iPhone 17` simulator.
- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 82 diagnostics tests passed, including the new effective-photo-policy diagnostics regression.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 247 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched result source, diagnostics tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected privacy-safe API comments, logger/redaction negative tests, synthetic sensitive-pattern fixtures, and planning-document privacy wording.

Remaining follow-up:

- Continue auditing app-facing projection consistency, especially convenience initializers that infer policy from mutable model contents.

### 2026-06-21 Reader Timeout Conversion Hardening Pass

Completed:

- Continued the reader lifecycle/concurrency audit with a focus on timeout task setup and scan cancellation behavior.
- Found that `startTimeoutTask(...)` converted a potentially huge finite `TimeInterval` to nanoseconds by multiplying a `Double` by `1_000_000_000` and converting directly to `UInt64` inside the task body. Near the upper safe bound this could become imprecise or trap during timeout task startup, making extreme but finite timeout input less predictable.
- Added `PassportReader.safeTimeoutNanoseconds(for:)` to reject nil, non-finite, zero, and negative timeouts; preserve normal fractional precision; and clamp extreme finite values before integer conversion.
- Updated `startTimeoutTask(...)` to use the checked conversion result before creating the timeout task.
- Added focused regressions for invalid timeout inputs, fractional nanosecond precision, and extreme finite timeout clamping without overflow.
- No README or migration update was needed; this is internal input hardening for an existing optional timeout parameter and preserves public API shape.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 84 diagnostics tests passed, including the new timeout conversion regressions.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 249 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched reader source, diagnostics tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected typed redacted `eventLogger.log(...)` calls, logger/redaction negative tests, synthetic sensitive-pattern fixtures, and planning-document privacy wording.

Remaining follow-up:

- Continue auditing reader lifecycle state around delayed CoreNFC callbacks, timeout cancellation, and scan-local display/progress handlers.

### 2026-06-21 DG12 Compact BCD Date Validation Pass

Completed:

- Audited data-group parser boundary behavior for quiet misparses that can surface as app-visible identity metadata.
- Found that `DataGroup12.parseDateOfIssue(...)` accepted the compact 4-byte BCD form by converting every nibble to hex. Invalid BCD nibbles such as `A-F` could therefore become a plausible-looking `dateOfIssue` string instead of failing closed.
- Updated compact BCD date decoding to validate every nibble as decimal `0...9` and throw `InvalidASN1Structure` for malformed BCD input.
- Added focused parser regressions proving valid compact BCD date-of-issue values still parse, and malformed compact BCD values are rejected before becoming app-visible model state.
- No README or migration update was needed; this preserves public API shape and tightens malformed chip-data handling for an existing parsed field.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 87 parser tests passed, including the compact BCD date validation regressions.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 251 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched DG12 parser, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing app-visible parsed identity fields for permissive fallback behavior that can convert malformed chip bytes into plausible values.

### 2026-06-21 DG11/DG12 Structured Date Validation Pass

Completed:

- Continued the app-visible parser permissiveness audit for identity metadata fields.
- Found that DG11 date of birth (`5F2B`) and DG12 ASCII date of issue (`5F26`) were decoded through the general LDS text decoder. That preserved multilingual text support for free-text fields, but it also let malformed date bytes such as alphabetic characters or punctuation become plausible app-visible date strings.
- Added an internal `LDSDateDecoder.decodeEightDigitDate(...)` helper that accepts only exactly eight ASCII digits and throws `InvalidASN1Structure` otherwise.
- Routed DG11 date of birth and DG12 ASCII date of issue through the strict date decoder. The existing compact DG12 BCD date path remains supported through its decimal-nibble validation.
- Kept free-text DG11/DG12 fields on `LDSStringDecoder` so issuing authority, names, places, observations, and nested other-person details continue to support UTF-8, UTF-16, Latin-1, and Windows-1252 inputs.
- Added focused parser regressions proving malformed DG11 date-of-birth and malformed DG12 ASCII date-of-issue values fail closed before becoming app-visible model state.
- No README or migration update was needed; this preserves public API shape and tightens malformed chip-data handling for existing parsed fields.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 89 parser tests passed, including the structured date validation regressions.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 253 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched DG11/DG12/date-decoder source, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing app-visible parser and model projections, especially DG1/MRZ field validation, name/date fallback precedence, and any certificate or verification metadata that can quietly become misleading support diagnostics.

### 2026-06-21 DG1 MRZ Character Validation Pass

Completed:

- Continued the app-visible identity parsing audit into DG1/MRZ, which feeds primary model fields, identity projections, passive-authentication hashes, and legacy compatibility accessors.
- Found that `DataGroup1` validated only the fixed MRZ layout length before slicing fields. Non-MRZ bytes, lowercase letters, punctuation, or invalid UTF-8 could therefore be accepted or silently decoded into empty strings before projection.
- Added DG1 MRZ byte validation before layout slicing. DG1 now accepts only ICAO MRZ characters `A-Z`, `0-9`, and `<`, and fails closed with `InvalidASN1Structure` for any other byte.
- Changed raw MRZ string storage to require successful UTF-8 decoding instead of assigning an optional string to the legacy internal element dictionary.
- Added a focused parser regression proving lowercase and non-UTF-8 MRZ bytes are rejected before model projection.
- Deferred full MRZ check-digit validation to a later dedicated pass because existing TD1/TD2 synthetic fixtures use placeholder check digits; this pass intentionally locks down the character/encoding boundary first without changing fixture semantics or public API shape.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 90 parser tests passed, including the DG1 invalid-MRZ-character regression.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 254 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched DG1 parser, parser tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected planning-document privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue the DG1/MRZ audit with full check-digit and field-semantic validation, then revisit name/date fallback precedence after valid-but-inconsistent DG1/DG11 combinations are covered by synthetic tests.

### 2026-06-21 DG1 MRZ Check-Digit And Date Semantics Pass

Completed:

- Continued the DG1/MRZ audit beyond character-set validation into ICAO check-digit and date-field semantics.
- Added DG1 check-digit validation for TD1, TD2, and TD3/other MRZ layouts before parsed fields are retained or projected. The parser now validates document-number, birth-date, expiry-date, optional/personal-number where applicable, and composite check digits for the supported layouts.
- Added explicit MRZ date-field validation so date-of-birth and document-expiry fields must be six ASCII digits. This prevents alphabetic MRZ characters from becoming app-visible dates even if a matching check digit could be computed.
- Updated parser and diagnostics fixtures to generate valid synthetic TD3 MRZ strings and TD1/TD2 check digits instead of relying on placeholder values.
- Added focused parser regressions for corrupted check digits and non-digit date fields with matching check digits.
- Kept the public API shape unchanged. Malformed DG1 chip data now fails closed with `InvalidASN1Structure` before identity projection.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 92 parser tests passed, including DG1 MRZ check-digit and date-field regressions.

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 84 diagnostics tests passed after updating the diagnostics DG1 fixture to generate valid check digits.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 256 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched DG1 parser, parser tests, diagnostics tests, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected logger/redaction negative tests, synthetic MRZ/APDU fixtures, and planning-document privacy wording.

Remaining follow-up:

- Continue the identity projection audit around valid-but-inconsistent DG1/DG11 combinations, including name fallback precedence and whether DG11 app-visible fields should supplement or override DG1 only when their structure is sufficiently trustworthy.

### 2026-06-21 DG1/DG11 Identity Projection Precedence Pass

Completed:

- Continued the app-visible identity projection audit after DG1 MRZ validation was tightened.
- Found that DG11 `fullName`, when present, always overrode the DG1 MRZ name even when the DG11 value was empty, whitespace-only, or unstructured free text. That could replace a validated DG1 name with blank or ambiguous app-visible fields.
- Changed `NFCPassportModel` name projection so DG11 names are preferred only when they contain a non-empty ICAO-style primary separator (`<<`). Empty, whitespace-only, or unstructured DG11 names now fall back to the validated DG1 MRZ name.
- Normalized projected name components by trimming filler-derived whitespace rather than surfacing padded MRZ filler as app-visible spacing.
- Changed DG11 personal-number projection so blank or whitespace-only DG11 values fall back to the DG1 optional-data value instead of overriding it with an empty app-visible string.
- Kept the public API shape unchanged. The behavior change is limited to safer, more predictable values returned by existing `NFCPassportModel` accessors and `PassportIdentityResult`.
- Updated `readme.md` to document DG1/DG11 name and personal-number fallback behavior.
- Added focused synthetic tests for empty DG11 name fallback, unstructured DG11 name fallback, valid structured DG11 name override, and blank DG11 personal-number fallback.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 96 parser tests passed, including the new DG1/DG11 projection precedence regressions.

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 84 diagnostics tests passed.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 260 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model source, parser tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing app-visible optional identity fields for precedence rules where optional DG11/DG12 values can still conflict with, obscure, or outlive stricter DG1-derived identity values.

### 2026-06-21 Optional Personal Number Nil Semantics Pass

Completed:

- Continued the optional identity-field projection audit after the DG1/DG11 name precedence pass.
- Found that DG1 optional-data/personal-number projection removed MRZ filler characters but returned the result even when all content was filler, producing an app-visible empty string for an optional identity field.
- Changed `NFCPassportModel.personalNumber` to route DG1 fallback values through the same optional identity normalizer used for DG11 values, so filler-only or whitespace-only optional identity values become `nil`.
- Extended the optional identity normalizer to treat MRZ filler (`<`) as absent content. This also means filler-only DG11 personal-number values fall back to DG1 instead of overriding it.
- Kept the public API shape unchanged. `personalNumber` was already optional; the behavior now uses `nil` for absent filler-only data rather than returning an empty string.
- Updated `readme.md` to document filler-only DG1/DG11 personal-number behavior.
- Added focused synthetic regressions for filler-only DG1 optional data and filler-only DG11 personal number fallback.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 98 parser tests passed, including the new filler-only personal-number regressions.

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 84 diagnostics tests passed.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 262 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model source, parser tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing remaining optional app-visible DG11/DG12 text fields for whether empty, whitespace-only, or filler-like values should be normalized to `nil` rather than surfaced as meaningful identity data.

### 2026-06-21 Optional DG11 Text Nil Semantics Pass

Completed:

- Continued the app-visible optional identity-field projection audit after the personal-number nil-semantics pass.
- Found that DG11 place-of-birth, residence-address, and phone projection returned decoded strings directly, allowing blank, whitespace-only, or filler-only values to surface as meaningful app-visible identity data.
- Changed `NFCPassportModel.placeOfBirth`, `residenceAddress`, and `phoneNumber` to trim edge whitespace and report blank or filler-only values as `nil`.
- Kept raw DG11 parsing behavior unchanged. The normalization is limited to app-facing `NFCPassportModel` projections and `PassportIdentityResult`.
- Kept the public API shape unchanged. These fields were already optional; absent-like values now use `nil` consistently.
- Updated `readme.md` to document optional DG11 text-field trimming and nil semantics.
- Added focused synthetic regressions for blank, filler-only, and trimmed optional DG11 place-of-birth, residence-address, and phone fields.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 101 parser tests passed, including the new optional DG11 text nil-semantics regressions.

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 84 diagnostics tests passed.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 265 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model source, parser tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing optional DG12 projected fields and diagnostics summaries for app-visible empty-string semantics. Also review raw model optional fields that are not yet exposed by `PassportIdentityResult` before deciding whether they need projection-time normalization.

### 2026-06-21 DG11/DG12 Calendar-Date Semantics Pass

Completed:

- Continued the DG12 projected-field audit and found that the shared LDS eight-digit date decoder accepted digit-only but impossible calendar dates such as invalid months or days.
- Tightened `LDSDateDecoder.decodeEightDigitDate(...)` to require a real Gregorian `YYYYMMDD` calendar date and reject year `0000`.
- Routed compact DG12 BCD issue dates through the same calendar-date validator after BCD digit extraction.
- Preserved valid ASCII and compact BCD date behavior for existing DG11/DG12 fixtures.
- Kept public API shape unchanged. Invalid DG11 date-of-birth and DG12 issue-date values now fail parsing instead of becoming app-visible strings.
- Updated `readme.md` to document the `YYYYMMDD` calendar-date guarantee for DG11/DG12 date fields.
- Added focused synthetic regressions for invalid DG11 date-of-birth, invalid DG12 ASCII issue date, and invalid DG12 BCD issue date.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 104 parser tests passed, including the new DG11/DG12 invalid-calendar-date regressions.

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 84 diagnostics tests passed.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched DG12 parser, shared LDS string/date decoder, parser tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue auditing diagnostics summaries and non-identity optional DG11/DG12 fields for app-visible empty-string semantics, retained sensitive data, and misleading defaults.

### 2026-06-21 Diagnostics Summary And DG1 MRZ Date Semantics Pass

Completed:

- Audited `PassportReaderDiagnosticsSummary`, `PassportChipReadResult`, `PassportDataGroupReadReport`, reader failure cleanup, and data-group read-report recording for accidental sensitive projection, misleading defaults, and empty-string semantics.
- Confirmed diagnostics summaries remain privacy-safe: success summaries project scan profile, photo policy, security policy, safe verification/trust metadata, data-group identifiers, and read-report statuses only; failure paths throw privacy-safe errors and scrub partial passport state rather than returning a partially populated diagnostics summary with retained raw data.
- Found a separate DG1 correctness gap while comparing date semantics: MRZ birth and expiry fields were checked for digits and matching check digits, but impossible `YYMMDD` month/day values with valid check digits could still parse and become app-visible identity dates.
- Tightened DG1 MRZ date validation to require a valid month and day. Two-digit-year handling remains conservative: February 29 is accepted when the two-digit year can represent a leap year, while impossible month/day combinations are rejected.
- Kept public API shape unchanged. Invalid DG1 MRZ date fields now fail parsing instead of becoming app-visible identity strings.
- Updated `readme.md` to document DG1 `YYMMDD` month/day validation alongside the DG11/DG12 `YYYYMMDD` calendar-date guarantee.
- Added focused synthetic regressions for invalid DG1 birth and expiry dates where the MRZ check digits still match.

Verification:

- Focused iOS Simulator parser tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test
  ```

  Result: 106 parser tests passed, including the new DG1 invalid-calendar-date regressions.

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 84 diagnostics tests passed.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 270 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched DG1 parser, parser tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

Remaining follow-up:

- Continue broad parser and reader-state passes, especially around retry-report semantics, unsupported-data-group final status clarity, and any remaining places where syntactically valid but semantically impossible identity values could be projected.

### 2026-06-21 Data-Group Read Report Final-State Pass

Completed:

- Audited data-group retry/read-report semantics for misleading final states.
- Found that `readDataGroup(...)` records `.failed` before classifying some read failures as final `.unsupported`, so safe diagnostics could contain both `failed` and `unsupported` for the same data group even though unsupported was the final outcome.
- Changed `NFCPassportModel.recordDataGroupReadStatus(...)` to keep requested/advertised context but remove stale transient terminal statuses when a stronger final status is recorded for the same data group.
- Kept public API shape unchanged. The report values are the same enum cases, but final `.read` or `.unsupported` outcomes no longer leave contradictory transient `.failed`, `.skippedByProfile`, or `.blockedByPolicy` terminal statuses for the same data group.
- Preserved optional authentication verification semantics. Existing precedence already treats unsupported DG14/DG15 reads as `.notSupported` rather than failed.
- Updated `readme.md` to document final read-report status behavior.
- Added focused diagnostics regressions for replacing transient `.failed` with final `.unsupported` and final `.read` while preserving `.requested` and `.advertised` context.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 86 diagnostics tests passed, including the new data-group read-report final-state regressions.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 272 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model source, data-group read-report type, diagnostics tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and diagnostics negative tests with synthetic sensitive-pattern terms.

### 2026-06-21 Redo-BAC Skip Path Pass

Status: implemented and verified.

- Audited `PassportReader.readDataGroup(...)` retry handling for status words classified as safe skip-and-redo-BAC outcomes.
- Found that the skip path removed the first entry from the original requested data-group queue instead of removing the current data group. It also set `redoBAC = true` and retried the same data group, which could convert a permanently inaccessible or missing optional group into a scan failure after two attempts instead of skipping it and continuing.
- Changed the skip path to remove the current data group by value, record a final `.unsupported` read-report outcome, reset BAC for following groups, and return `nil` so the outer read loop continues with the next selected data group.
- Added a focused queue-removal regression so skip handling cannot silently remove COM, SOD, DG1, or any other earlier requested group when the current optional group is skipped.
- Cleaned a Swift warning in the touched diagnostics test file by making the weak reader reference immutable.
- Updated README support-diagnostics wording to explain that chip-reported inaccessible or missing optional groups are reported as unsupported after BAC reset for later groups.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 87 diagnostics tests passed, including the new skip-queue regression. An initial run surfaced a Swift 6 main-actor isolation issue in the new test and a pre-existing warning in the touched diagnostics test file; both were fixed and the focused suite was rerun cleanly.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 273 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched reader source, diagnostics tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected typed redacted `eventLogger.log(...)` calls, README/plan privacy wording, and diagnostics negative tests with synthetic sensitive-pattern terms.

Remaining follow-up:

- Continue reader-state and retry-path audits, especially scan cancellation across async retries and report ordering that could still make support summaries hard to interpret.

### 2026-06-22 Legacy Read-All Requested-Status Pass

Status: implemented and verified.

- Continued the reader-state/support-diagnostics audit after the redo-BAC skip path fix.
- Found that legacy empty-tag read-all scans resolved the initial `dataGroupsToRead` list to empty, recorded requested statuses, and only then appended COM/SOD as mandatory startup groups. That meant safe data-group read reports could omit `.requested` context for COM/SOD even though those groups are deliberately requested before COM expansion.
- Centralized initial data-group request calculation so default empty-tag scans return COM/SOD with `readAllDataGroups = true`, while security-policy-driven minimal scans such as `.identityOnly` still return their explicit minimal set without enabling read-all expansion.
- Moved requested-status recording after initial request resolution, so diagnostics preserve the effective startup request without changing which groups are read.
- Added a focused regression for legacy read-all startup groups and the identity-only empty-tags path.
- Updated README support-diagnostics wording to document requested COM/SOD startup context for legacy read-all scans.

Verification:

- Focused iOS Simulator diagnostics tests passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests test
  ```

  Result: 88 diagnostics tests passed, including the new legacy read-all request regression.

- Full release gate passed:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
  ```

  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 274 tests with no failures. Risky-pattern output remained expected documentation, negative-test fixtures, internal APDU/key terminology, OpenSSL type-name, NFC transport type names, and redacted event hits only.

- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched reader source, diagnostics tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected typed redacted `eventLogger.log(...)` calls, README/plan privacy wording, and diagnostics negative tests with synthetic sensitive-pattern terms.

### 2026-06-22 SOD Hash Structure Validation Pass

Status: implemented and verified in this pass.

- Continued parser/authentication-boundary auditing, focusing on the LDS Security Object content that drives passive data-group hash verification.
- Found that `NFCPassportModel.parseSODSignatureContent(...)` validated the digest algorithm and hash-list shape, but did not require the first LDS Security Object child to be an INTEGER version. A malformed SOD content body with a NULL or arbitrary first child could still be accepted for data-group hash verification if later fields looked valid.
- Tightened SOD hash-list parsing to require a valid INTEGER version, a digest-algorithm SEQUENCE, and exactly two children in each data-group hash entry.
- Added focused parser regressions for malformed version fields and overstuffed data-group hash entries.
- Updated README verification wording to document that the LDS Security Object hash list is structurally validated before it can drive data-group hash status.
- Verification:
  - Focused parser test pass:
    `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test`
    Result: `DataGroupParsingTests` ran 108 tests with no failures.
  - Full release gate:
    `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
    Result: iOS package build, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 276 tests with no failures.
  - Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched model source, parser tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

### 2026-06-22 SecurityInfos Shape Strictness Pass

Status: implemented and verified in this pass.

- Continued parser/authentication-boundary auditing, focusing on SecurityInfos parsed from EF.CardAccess, EF.CardSecurity, and DG14 before PACE/CAM/Chip Authentication decisions.
- Found that `SecurityInfosParser.parse(_:)` still accepted a top-level `SEQUENCE` even though SecurityInfos is a `SET OF SecurityInfo`. It also accepted SecurityInfo records with more than the allowed OID, required-data, and optional-data fields, silently ignoring the extra chip-controlled fields.
- Tightened SecurityInfos parsing to require a top-level SET and to reject SecurityInfo records unless they contain exactly two or three children.
- Preserved compatibility for well-formed unknown OIDs by continuing to project them as redacted `UnknownSecurityInfo` values.
- Added focused parser regressions for sequence-wrapped SecurityInfos and overlong recognized/unknown SecurityInfo records.
- Updated README PACE/CAM wording to document that well-formed unknown SecurityInfo records are preserved, while malformed wrappers or overlong records fail closed.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test`
  Result: `DataGroupParsingTests` ran 110 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 278 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched SecurityInfos parser source, parser tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

### 2026-06-22 SOD CMS Shape Strictness Pass

Status: implemented and verified in this pass.

- Continued the parser/authentication-boundary audit, focusing on SOD CMS accessors that feed passive authentication signature and encapsulated-content checks.
- Found that `SOD.signedDataItem()` accepted the first nested `SEQUENCE` inside the CMS explicit `[0]` wrapper instead of requiring the signed-data body to be the sole direct child. `getEncapsulatedContent()` also accepted the first `[0]`/OCTET content inside `encapContentInfo` without confirming the LDS Security Object content type or that the explicit content held exactly one OCTET STRING.
- Tightened SOD CMS parsing to require a direct two-child CMS ContentInfo, a direct single signed-data child, expected SignedData field tags, a direct LDS Security Object `eContentType`, and exactly one encapsulated OCTET STRING.
- Tightened signer-info and digest-algorithm container checks so malformed SET contents fail closed instead of being searched loosely for the first sequence.
- Added focused parser regressions for extra sequences in the CMS explicit signed-data wrapper, unexpected encapsulated content type, and extra encapsulated OCTET children.
- Updated README verification wording to document that the SOD CMS wrapper and LDS Security Object content type are structurally validated before signature/hash status can be driven from them.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests test`
  Result: `DataGroupParsingTests` ran 113 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 281 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over the touched SOD source, parser tests, README, and planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining changed-file hits were expected README/plan privacy wording and negative parser-test assertions with synthetic MRZ/APDU terms.

### 2026-06-22 PACE Integrated Mapping Cipher Metadata Pass

Status: implemented and verified in this pass.

- Shifted the audit angle from SOD/CMS parsing to PACE authentication response and mapping-boundary behavior.
- Found that Integrated Mapping block-length selection used `try? expectedNonceLength(...) ?? 16`, so unsupported cipher/key-length metadata could advance with a guessed 16-byte passport-nonce block length. A later encryption helper would usually fail, but the failure would be less precise and would happen after the code had accepted malformed PACE metadata into the IM field-building path.
- Changed `integratedMappingInputBlockLength(...)` to throw and propagate `UnsupportedCipherAlgorithm` instead of defaulting to 16.
- Added a focused regression proving AES with an unsupported 512-bit key length fails before Integrated Mapping encryption work.
- No public API or README update was needed; this is internal PACE fail-closed hardening.
- Focused core test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests test`
  Result: `NFCPassportReaderTests` ran 81 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 282 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `PACEHandler.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected secure-messaging/APDU/key synthetic test fixtures and planning-document privacy wording.

### 2026-06-22 CardSecurity CMS Shape Strictness Pass

Status: implemented and verified in this pass.

- Shifted the audit angle from SOD/PACE hardening to EF.CardSecurity CMS and SecurityInfos extraction.
- Found that `SecurityInfosParser.signedEncapsulatedContent(from:)` still used loose descendant searches inside CMS SignedData. Malformed wrappers with extra direct children, or EncapsulatedContentInfo values with unexpected child ordering, could be accepted if a later SEQUENCE/A0/OCTET happened to contain parseable SecurityInfos.
- Hardened CardSecurity unsigned-content extraction to require a direct SignedData wrapper, exactly one explicit SignedData child, version and digest-algorithm fields in the expected positions, a direct EncapsulatedContentInfo SEQUENCE with exactly an OID plus one explicit OCTET child, and a direct signerInfos SET.
- Added focused regressions proving EF.CardSecurity rejects an extra direct child in the explicit SignedData wrapper and rejects unexpected EncapsulatedContentInfo children instead of searching past them.
- No public API or README update was needed; this is internal fail-closed CMS parsing hardening for chip-controlled CardSecurity data.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 115 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 284 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `SecurityInfosParser.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser privacy assertions with synthetic MRZ/APDU terms and planning-document privacy wording.

### 2026-06-22 SOD Signed-Attributes Shape Strictness Pass

Status: implemented and verified in this pass.

- Shifted the audit angle from outer CMS wrappers to inner SOD signed-attribute semantics used by passive authentication.
- Found that `SOD.getMessageDigestFromSignedAttributes()` searched inside the `messageDigest` attribute SET for any OCTET value. A malformed signed attribute with extra values, or with a non-OCTET first value followed by an OCTET, could still be accepted as if the signed attributes were canonical.
- Hardened message-digest extraction to require exactly one `messageDigest` attribute, exactly two attribute children, an attribute-values SET, and exactly one OCTET value inside that SET.
- Added focused regressions proving SOD signed attributes reject extra digest values and reject a non-OCTET first value even when a later OCTET contains the expected digest.
- No public API or README update was needed; this is internal passive-authentication fail-closed parsing hardening.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 117 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 286 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `SOD.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser privacy assertions with synthetic MRZ/APDU terms and planning-document privacy wording.

### 2026-06-22 Model Cleanup Authentication Status Reset Pass

Status: implemented and verified in this pass.

- Shifted the audit angle from parser strictness to model cleanup and result-state consistency.
- Found that `NFCPassportModel.removeSensitiveDataForPrivacy()` reset raw data, verification, active-authentication, and chip-authentication state, but left `BACStatus` and `PACEStatus` unchanged. A model cleaned for privacy could therefore still report stale authentication outcomes from a previous read.
- Reset `BACStatus` and `PACEStatus` to `.notDone` during sensitive cleanup, matching the existing chip-authentication reset.
- Expanded the sensitive-cleanup regression to seed BAC, PACE, and chip-authentication statuses before cleanup and assert that all authentication status fields return to `.notDone`.
- No public API or README update was needed; this is an internal cleanup invariant and compatibility-preserving behavior correction.
- Focused diagnostics test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests`
  Result: `PassportReaderLoggingTests` ran 88 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 286 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `NFCPassportModel.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected logger/redaction negative tests and planning-document privacy wording.

### 2026-06-22 DG2 Cleanup Metadata Scrub Pass

Status: implemented and verified in this pass.

- Continued the privacy cleanup audit from the angle of externally retained data-group references after `NFCPassportModel.removeSensitiveDataForPrivacy()` has scrubbed and released the model's data-group dictionary.
- Found that `DataGroup2.removeSensitiveDataForPrivacy()` cleared retained face image bytes and item arrays, but left parsed biometric metadata such as image counts, record lengths, image dimensions, feature counts, and quality/source fields on the retained `DataGroup2` object.
- Reset DG2 biometric metadata fields to default values during cleanup so a scrubbed retained DG2 no longer describes the removed face image record.
- Expanded the existing retained-data-group cleanup regression to assert representative DG2 metadata is populated before cleanup and that all DG2 image metadata fields return to zero after cleanup.
- No public API or README update was needed; this is an internal cleanup invariant that preserves source compatibility while reducing retained biometric metadata.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 117 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 286 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `DataGroup2.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser privacy assertions, synthetic MRZ/APDU fixtures, and planning-document privacy wording.

### 2026-06-22 CardAccess/CardSecurity Cleanup Reference Scrub Pass

Status: implemented and verified in this pass.

- Continued the cleanup/reference-retention audit, focusing on parsed chip security metadata that can be shared outside the model during a scan.
- Found that `NFCPassportModel.removeSensitiveDataForPrivacy()` nilled `cardAccess` and `cardSecurity`, but did not scrub the referenced objects first. An outside reference, such as one retained from the internal tracking delegate's `readCardAccess(cardAccess:)` callback, could keep parsed PACE/CardSecurity `SecurityInfo` metadata after the working model was cleaned.
- Added cleanup hooks to `CardAccess` and `CardSecurity`. `CardAccess` now clears parsed `securityInfos`; `CardSecurity` clears parsed `securityInfos`, resets trust flags, and clears any retained signed CMS bytes.
- Updated model cleanup to scrub `cardAccess` and `cardSecurity` before releasing them.
- Added a focused regression that retains `CardAccess` and `CardSecurity` references outside the model, runs model privacy cleanup, and verifies the outside references no longer expose PACE/CardSecurity metadata or trust flags.
- No public API or README update was needed; these are internal cleanup hooks and do not change app-facing scan result types.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 118 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `CardAccess.swift`, `CardSecurity.swift`, and `NFCPassportModel.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser privacy assertions, synthetic MRZ/APDU fixtures, and planning-document privacy wording.

### 2026-06-22 COM Cleanup Metadata Scrub Pass

Status: implemented and verified in this pass.

- Continued the cleanup/reference-retention audit into low-risk chip capability metadata that can still reveal parsed chip structure after the model releases its data-group dictionary.
- Found that `COM` inherited the base raw TLV cleanup, but an externally retained `COM` reference kept parsed LDS `version`, `unicodeVersion`, and `dataGroupsPresent` values after `NFCPassportModel.removeSensitiveDataForPrivacy()`.
- Reset COM version fields to `Unknown` and clear the advertised data-group list during privacy cleanup, then call the base raw-buffer scrub.
- Extended the retained-data-group cleanup regression to include COM, verifying parsed version/group metadata and raw COM buffers are populated before cleanup and cleared afterward.
- No public API or README update was needed; this is an internal cleanup invariant and compatibility-preserving behavior correction.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 118 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 287 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `COM.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser privacy assertions, synthetic MRZ/APDU fixtures, and planning-document privacy wording.

### 2026-06-22 DG15 Cleanup Regression Coverage Pass

Status: implemented and verified in this pass.

- Continued the retained-reference cleanup audit across data-group subclasses, with a focus on objects that hold native resources rather than Swift byte arrays or text fields.
- Confirmed that `DataGroup15.removeSensitiveDataForPrivacy()` already frees and nils retained OpenSSL public-key pointers, but the model-level retained data-group cleanup regression did not cover DG15.
- Extended `testModelPrivacyCleanupScrubsRetainedDataGroupPayloadsBeforeReleasingReferences()` to include a retained synthetic DG15 object, verify an EC/RSA public key is present before model cleanup, and assert both key pointers plus raw data/body buffers are cleared afterward.
- Moved the long synthetic DG15 public-key fixture behind a shared test helper so both the existing DG15 parser test and the cleanup regression use the same synthetic data without duplicating a long hex literal in test bodies.
- No public API or README update was needed; this is test coverage for an existing internal cleanup invariant.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 118 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 287 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A narrow scan over `DataGroupParsingTests.swift` and this planning document found no new production raw logging, direct `Logger`, `os_log`, `print`, filesystem, clipboard, persistence, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink. Remaining hits were expected parser privacy assertions, synthetic MRZ/APDU fixtures, and planning-document privacy wording.

### 2026-06-22 DG15 Unsupported Public Key Fail-Closed Pass

Status: implemented and verified in this pass.

- Shifted the parser audit to malformed/unsupported-but-well-formed chip structures that could be accepted as "missing capability" instead of rejected as bad DG content.
- Found that `DataGroup15.parse(_:)` freed valid DER public keys with unsupported OpenSSL key types and then accepted the DG15 object with no RSA or EC key. That could blur an unsupported Active Authentication key algorithm with a passport that simply lacks an active-authentication key.
- Changed DG15 parsing to fail closed with `InvalidASN1Structure` when a public key cannot be loaded or when the loaded key is not RSA or EC. Unsupported native key pointers are still freed before throwing.
- Added a synthetic DSA SubjectPublicKeyInfo fixture wrapped as DG15 and a regression asserting the parser rejects it with `InvalidASN1Structure`.
- Removed a stale DG15 test comment that incorrectly described the fixture as a cut-down DG7 image record.
- No public API or README update was needed; this is an internal parser correctness and fail-closed behavior correction.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 119 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 288 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `DataGroup15.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser privacy assertions, synthetic MRZ/APDU fixtures, and planning-document privacy wording.

### 2026-06-22 EF.CardSecurity Present-Data Fail-Closed Pass

Status: implemented and verified in this pass.

- Shifted the reader/session audit through the runtime PACE setup path and reviewed cancellation, stale scan, timeout, and cleanup invariants.
- Found that EF.CardSecurity was treated as optional in two different ways: read failures were ignored, which preserves compatibility because EF.CardSecurity is optional, but successfully read EF.CardSecurity bytes were also parsed with `try?`, allowing malformed present CMS/SecurityInfos content to be silently dropped.
- Preserved optional read behavior for absent/unavailable EF.CardSecurity, but changed present bytes to parse through a throwing reader helper so malformed EF.CardSecurity fails closed instead of becoming "not present".
- Kept CMS signature verification failure non-fatal and non-trusting. This remains compatible with the documented CAM behavior: only trusted EF.CardSecurity can satisfy CAM early, and untrusted or unverifiable EF.CardSecurity falls back to DG14/separate Chip Authentication paths.
- Added a focused regression proving the reader rejects malformed present EF.CardSecurity data at the storage boundary.
- No public API or README update was needed; this is an internal security-metadata parsing correction that aligns runtime behavior with the existing documented fail-closed parser policy.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 120 tests with no failures after an intermediate test-only actor-isolation fix and an adjustment to assert rejection without pinning an internal parser error spelling.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 289 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `PassportReader.swift` found no new raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink; remaining hits were existing typed redacted `eventLogger.log(...)` calls. A broader touched-file scan only hit expected parser privacy assertions, synthetic MRZ/APDU/image fixtures, and planning-document privacy wording.

### 2026-06-22 Chip Authentication Public-Key Cleanup Pass

Status: implemented and verified in this pass.

- Shifted the audit to native OpenSSL resource ownership and retained-reference cleanup, focusing on objects that can outlive their container after privacy cleanup.
- Found that `ChipAuthenticationPublicKeyInfo` owned an OpenSSL `EVP_PKEY` but only freed it in `deinit`. If a key-info object escaped before `CardAccess`, `CardSecurity`, or `ChipAuthenticationHandler` cleanup, the container could clear its array while the retained key-info object still held the native public key.
- Added a `SecurityInfo.removeSensitiveDataForPrivacy()` hook and overrode it in `ChipAuthenticationPublicKeyInfo` to free and nil the native key immediately.
- Updated `CardAccess`, `CardSecurity`, and `ChipAuthenticationHandler` cleanup to scrub contained `SecurityInfo` values before releasing arrays.
- Changed Chip Authentication and PACE-CAM verification key use to fail closed when a key-info object has already been scrubbed.
- Added focused regressions proving direct key-info cleanup clears the retained native key and handler cleanup also clears a retained key-info object.
- No public API or README update was needed; this is internal native-resource and retained-reference cleanup hardening.
- Focused core test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests`
  Result: `NFCPassportReaderTests` ran 82 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 290 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over the touched SecurityInfo/CardAccess/CardSecurity/Chip Authentication/PACE-CAM sources found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected secure-messaging/APDU/key synthetic test fixtures and planning-document privacy wording.

### 2026-06-22 DG14 SecurityInfo Cleanup Pass

Status: implemented and verified in this pass.

- Continued the retained-reference cleanup audit across containers that hold parsed `SecurityInfo` values.
- Found that DG14 retained parsed `SecurityInfo` objects but its cleanup only cleared the `securityInfos` array. After the Chip Authentication public-key cleanup pass, DG14 still needed to call the contained cleanup hook before releasing its array, otherwise an externally retained DG14 `ChipAuthenticationPublicKeyInfo` could keep an OpenSSL public key after model privacy cleanup.
- Updated `DataGroup14.removeSensitiveDataForPrivacy()` to scrub contained `SecurityInfo` values before clearing the array and base data-group bytes.
- Added a synthetic DG14 Chip Authentication public-key fixture and regression proving model privacy cleanup clears a retained DG14 key-info object's native public key.
- No public API or README update was needed; this is internal cleanup consistency hardening for DG14 authentication metadata.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 121 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 291 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `DataGroup14.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 DG2 Facial-Image Count Fail-Closed Pass

Status: implemented and verified in this pass.

- Shifted the parser audit to nested ISO/IEC 19794-5 count invariants in DG2 face-image payloads.
- Found that `DataGroup2.parseISO19794_5(data:)` accepted a declared facial-image count of `0` or an oversized value by falling through to the single-record parser path. That could retain one parsed image while the parsed metadata claimed zero facial images, or accept an unrealistic count that should have been rejected.
- Changed DG2 parsing to fail closed unless the nested facial-image count is in the supported `1...32` range before any image payload is appended.
- Added focused regressions for zero and oversized declared facial-image counts, including checks that a previously retained valid image remains unchanged after the malformed parse attempt.
- No public API or README update was needed; this is an internal malformed-DG2 rejection and retained-image consistency correction.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 123 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully.
- Full simulator test recount:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'`
  Result: the full simulator suite ran 293 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `DataGroup2.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 COM Version Fail-Closed Pass

Status: implemented and verified in this pass.

- Shifted the parser consistency audit to required COM metadata that controls app-visible LDS version values and advertised data-group expansion.
- Found that malformed COM LDS version or Unicode version fields were accepted as `"Unknown"` while parsing continued and `dataGroupsPresent` could still drive subsequent reads. That contradicted the fail-closed policy for present but malformed chip metadata.
- Changed COM parsing to reject required version fields unless they have the exact ICAO decimal ASCII shape expected for LDS version (`AABB`) and Unicode version (`AABBCC`).
- Added focused regressions for wrong-length and non-decimal LDS/Unicode version values.
- No public API or README update was needed; `"Unknown"` remains the cleanup/no-COM fallback, while present malformed COM bytes now fail closed.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 125 tests with no failures.
- Full release gate:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully.
- Full simulator test recount:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5'`
  Result: the full simulator suite ran 295 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `COM.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 Replaced DataGroup Cleanup Pass

Status: implemented and verified in this pass.

- Shifted the audit to mutable model state and stale-reference behavior when a data group is replaced after prior parsing or verification.
- Found that `NFCPassportModel.addDataGroup(_:dataGroup:)` reset verification state before replacement, but overwrote an existing data-group reference without scrubbing the old object. If any code retained the old parsed object, its raw bytes and parsed sensitive fields could remain available after replacement.
- Updated `addDataGroup` to call `removeSensitiveDataForPrivacy()` on the existing data-group object before replacing it, while preserving re-addition of the same object without self-scrubbing the new value.
- Extended the existing replacement regression to prove the old retained DG1 object has its MRZ-derived parsed fields plus raw data/body buffers cleared, while the replacement DG1 remains populated and usable.
- No public API or README update was needed; this is internal data-minimization hardening for replacement paths.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 125 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 295 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `NFCPassportModel.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 SecurityInfo Version Fail-Closed Pass

Status: implemented and verified in this pass.

- Shifted the audit to semantic validation of recognized SecurityInfo records after the structural ASN.1 parser hardening.
- Found that recognized PACE, Chip Authentication, and Active Authentication SecurityInfo records validated field shape but accepted unsupported version integers. That could make future or malformed security metadata look like currently supported metadata and influence PACE/CA selection or Active Authentication metadata projection.
- Changed recognized SecurityInfo construction to fail closed unless PACE version is `2`, Chip Authentication version is `1`, and Active Authentication version is `1`.
- Added parser regressions proving unsupported recognized versions are rejected with `InvalidASN1Structure`.
- No public API or README update was needed; this is an internal malformed-security-metadata rejection that preserves existing supported-version behavior.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 126 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 296 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `SecurityInfo.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 SOD Version Fail-Closed Pass

Status: implemented and verified in this pass.

- Shifted the verification audit to semantic validation of the LDS Security Object content that drives passive-authentication data-group hash status.
- Found that `NFCPassportModel.parseSODSignatureContent(data:)` required the SOD version field to be an ASN.1 integer, but accepted any non-negative integer value. ICAO LDS Security Object parsing in this fork only implements version `0`; accepting a future or malformed version could make unsupported SOD hash semantics look like the current supported format.
- Changed SOD signature-content parsing to fail closed unless the version integer is exactly `0`.
- Added a focused parser regression proving a well-formed but unsupported SOD version is rejected with `UnableToParseSODHashes`.
- No public API or README update was needed; this is internal passive-authentication parser hardening and preserves current version-0 behavior.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 127 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 297 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `NFCPassportModel.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 No-Photo Result Projection Privacy Pass

Status: implemented and verified in this pass.

- Shifted the audit to app-facing result projection consistency, especially whether the effective photo policy is honored by every public result field rather than only by the image-byte payload.
- Found that `PassportChipReadResult(passport:photoPolicy:)` suppressed `faceImageData` for `photoPolicy: .skip`, but still built `identity` from the raw model projection. If an internal model already contained DG2, `PassportChipReadResult.identity.hasFaceImage` could reveal that a face-image payload existed despite the caller requesting a no-photo result projection.
- Changed chip-level result projection to build `PassportIdentityResult` with the effective `PassportPhotoPolicy`. `PassportIdentityResult.hasFaceImage` is now `false` when projected through `PassportChipReadResult` with `.skip`, even if DG2 is already present internally. Direct `NFCPassportModel.identityResult` keeps the existing default `.read` projection for internal model inspection.
- Updated the focused diagnostics regression to prove `.skip` suppresses both image bytes and the face-image presence boolean, while `.read` still reports the available DG2 image.
- Updated `readme.md` to document the no-photo projection behavior and privacy rationale for host apps.
- Focused diagnostics test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests`
  Result: `PassportReaderLoggingTests` ran 88 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 297 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `PassportChipReadResult.swift` and `PassportIdentityResult.swift` found no `try!`, forced casts, runtime traps, forced `first`/`last`, raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected README/plan privacy wording and existing diagnostics negative tests with synthetic sensitive-pattern terms.

### 2026-06-22 Result Diagnostics Security Policy Pass

Status: implemented and verified in this pass.

- Continued the app-facing result consistency audit after the no-photo projection fix, focusing on whether support diagnostics reflect the effective policy decisions that actually shaped the scan.
- Found that `PassportChipReadResult` threaded the effective photo policy into `PassportReaderDiagnosticsSummary`, but always let the diagnostics summary use its default security policy. Public results from `.identityOnly`, `.notaryRecommended`, or custom stricter policies could therefore carry misleading support metadata even though the scan itself used the requested policy.
- Added a `securityPolicy` parameter to chip result construction and threaded it from every `readPassportIdentity` overload through `makeIdentityResultAndScrubPassport(...)`.
- Updated the focused diagnostics regression to prove `PassportChipReadResult.diagnosticsSummary.securityPolicy` preserves a non-default policy and still defaults to `.default` for direct internal test construction.
- Updated `readme.md` to describe diagnostics summary policy fields as effective policy values.
- Focused diagnostics test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/PassportReaderLoggingTests`
  Result: `PassportReaderLoggingTests` ran 88 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 297 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `PassportChipReadResult.swift`, `PassportIdentityResult.swift`, and `PassportReader.swift` found no new raw `print`, direct `Logger`, `os_log`, filesystem, clipboard, persistence, network, raw export, runtime trap, force unwrap, force cast, or sensitive diagnostic sink; remaining production hits were existing typed redacted `eventLogger.log(...)` calls. A broader touched-file scan only hit expected README/plan privacy wording, existing diagnostics negative tests with synthetic sensitive-pattern terms, and internal APDU terminology.

### 2026-06-22 TD1 Composite Check Digit Range Pass

Status: implemented and verified in this pass.

- Shifted the audit to app-visible identity parser correctness, especially MRZ fields that drive normalized document identity values.
- Found that TD1 composite check-digit validation included middle-line nationality bytes. ICAO Doc 9303 Part 5 section 4.2.4 defines the TD1 composite check digit over upper-line positions 6-30 and middle-line positions 1-7, 9-15, and 19-29, explicitly excluding middle-line positions 8 and 16-18. The parser already excluded sex at position 8, but incorrectly included nationality at positions 16-18.
- Changed TD1 composite validation to exclude nationality and validate the ICAO-defined ranges.
- Updated the valid TD1 parser fixture to compute the composite check digit without nationality, and added a negative regression proving the old nationality-including composite is rejected.
- No public API or README update was needed; this is internal MRZ correctness hardening that preserves the same safe public projection surface.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 128 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 298 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `DataGroup1.swift` found no forced operations, runtime traps, raw logging, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 TD1 Long Document Number Pass

Status: implemented and focused-test verified in this pass.

- Continued the DG1 TD1 parser audit against ICAO Doc 9303 Part 5, focusing on document-number layouts rather than only fixed-width check digits.
- Found that `DataGroup1` only supported the ordinary TD1 document-number check digit at upper-line position 15. ICAO Doc 9303 Part 5 notes that document numbers longer than nine characters place a filler at position 15, continue the document number at the beginning of the upper-line optional field, then place the long-document-number check digit after that continuation followed by filler.
- Added a TD1 document-number layout helper that validates and projects both ordinary and long TD1 document numbers before fields are retained. Long TD1 document numbers now project the full document number into `5A`, project the actual long-number check digit into `5F04`, and do not mix the continuation/check/filler bytes into optional data `53`.
- Added focused synthetic parser coverage for a valid TD1 long document number and for an otherwise-valid TD1 long document number with a bad long-number check digit.
- No public API or README update was needed; this is internal parser correctness hardening that preserves the existing safe public projection surface while accepting a valid ICAO TD1 layout previously rejected.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 130 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: the first run caught trailing whitespace in an existing DG12 parser test block, which was fixed before handoff. The rerun completed successfully, including iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting. The full simulator suite ran 300 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `DataGroup1.swift` found no forced operations, runtime traps, raw logging, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 TD1 Long Document Optional Data Pass

Status: implemented and focused-test verified in this pass.

- Revisited the new TD1 long-document-number support against ICAO Doc 9303 Part 5 note j and section 4.2.4 before moving on to a different audit surface.
- Found that the first long-document-number helper was too strict after the long-number check digit: it required every remaining upper-line position to be filler. ICAO requires the long-number check digit to be followed by a filler marker, but the remaining upper-line optional positions can still carry issuer optional data.
- Relaxed long TD1 document-number parsing to require the filler marker immediately after the long-number check digit while preserving non-filler upper-line optional data after that marker in `53`. Filler-only tails remain omitted from `53` so the document-number continuation, check digit, and marker are not projected as optional data.
- Added a focused synthetic parser regression for a long TD1 document number with upper-line optional data after the check-digit marker.
- No public API or README update was needed; this is internal parser compatibility hardening that preserves the same safe public projection surface.
- Focused parser test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/DataGroupParsingTests`
  Result: `DataGroupParsingTests` ran 131 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 301 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `DataGroup1.swift` found no forced operations, runtime traps, raw logging, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected parser JPEG test names, negative APDU assertions, and planning-document privacy wording.

### 2026-06-22 PACE Authentication Response Strictness Pass

Status: implemented and focused-test verified in this pass.

- Shifted the audit to malformed cryptographic response boundaries, especially TLV parsing that happens after PACE shared-secret derivation.
- Found that `PACEHandler.authenticationTokenAndCAMData(from:)` selected the first authentication token object (`0x86`) and first encrypted CAM object (`0x8A`) while ignoring duplicate or unknown TLV objects in the final PACE authentication response.
- Hardened the parser to require exactly one authentication token object, at most one encrypted CAM object, and no unknown objects. Malformed cases now fail closed with privacy-safe PACE errors before token comparison or CAM verification.
- Added focused synthetic regressions for duplicate token objects, duplicate CAM objects, and unknown objects in the final PACE response. Existing tests still cover CAM-before-token ordering, missing token, wrong token length, and constant-time token comparison.
- No public API or README update was needed; this is internal protocol strictness hardening that preserves app-facing error redaction.
- Focused core test pass:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/NFCPassportReaderTests`
  Result: `NFCPassportReaderTests` ran 85 tests with no failures.
- Release check:
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh`
  Result: iOS package build, iOS build-for-testing, full iOS Simulator package tests, API surface check, privacy scan, NFC boundary check, whitespace check, and risky-pattern reporting completed successfully. The full simulator suite ran 304 tests with no failures.
- Final whitespace and targeted risky-pattern scans passed. `git diff --check` produced no output. A production sink scan over `PACEHandler.swift` found no forced operations, runtime traps, raw logging, persistence, network, raw export, or related diagnostic sinks. A broader touched-file scan only hit expected secure-messaging/APDU/key synthetic test fixtures and planning-document privacy wording.

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
