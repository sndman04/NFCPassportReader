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
