# NFCPassportReader

This fork handles reading NFC-enabled passports for iOS 26+ apps using Swift 6.3 and CoreNFC.

## Fork Branch Policy

This fork's `main` branch is the maintained Notary/privacy release line. It includes the privacy-safe public APIs documented below, including `readPassportIdentity(...)`, `PassportChipReadResult`, `PassportScanOptions`, and typed redacted diagnostics.

Historical upstream snapshots are kept on explicitly named branches such as `upstream/2.3.1` for comparison and future merge work. Apps should pin a `notary-*` annotated release tag rather than a moving branch.

**Version 2 (and the main branch) now uses Swift Async/Await for communication.  If you need an earlier version, please use 1.1.9 or below!**

Supported features:
* Basic Access Control (BAC)
* Secure Messaging
* Reads and verifies LDS data groups without exposing raw chip data through public app APIs. COM, DG1, DG2, DG7, DG11, DG12, DG14, DG15, and SOD have typed parsers; DG3, DG4, DG5, DG6, DG8, DG9, DG10, DG13, and DG16 are retained internally as opaque typed data groups for hashing.
* Passive Authentication with structured LDS Security Object hash parsing and CMS verification fallback.
* Active Authentication with RSA and ECDSA DG15 public-key detection.
* Chip Authentication (ECDH DES/AES paths have focused coverage; DH DES/AES metadata and implementation paths are present, with real-chip validation still required)
* PACE with MRZ, CAN, PIN, or PUK password references. When a chip advertises multiple PACE options, implemented Generic Mapping (GM), Integrated Mapping (IM), and ECDH Chip Authentication Mapping (CAM) options are eligible. CAM can establish PACE secure messaging and validates the CAM proof against trusted EF.CardSecurity chip-authentication keys or DG14 chip-authentication public keys when available.
* Privacy-first public API returning `PassportChipReadResult` instead of raw passport data.
* Uses Async/Await

This is still very early days - the code is by no means perfect and there are still some rough edges  - there ARE most definitely bugs and I'm sure I'm not doing things perfectly. 

It reads and verifies my passport (and others I've been able to test) fine, however your mileage may vary.

## Installation
### Swift Package Manager (recommended)

NFCPassportReader may be installed via Swift Package Manager, by pointing to this repo's URL.

This fork requires Xcode 26.5 or newer with Swift 6.3 support. The package manifest declares SwiftPM tools 6.3 and an iOS 26.0 minimum deployment target.

## Privacy-safe fork usage

This fork is intended for apps that need passport chip reading without leaking identity-document data through logs, diagnostics, or broad raw-data APIs. Logging is off by default, and opt-in logging is typed and redacted.

Create the Passport MRZ key in app memory from the passport number, date of birth, and expiry date, including their checksums. Dates are in YYMMDD format. Treat the resulting access key as sensitive: do not log, persist, upload, or include it in bug reports.

For example:

```
<passport number><passport number checksum><date of birth><date of birth checksum><expiry date><expiry date checksum>
```

Then create a `PassportReader` and call the privacy-first async `readPassportIdentity` API. Prefer reviewed scan options over ad hoc data-group lists where possible.

Progress events are structured and redacted; they do not include MRZ values, APDUs, keys, decrypted data groups, or image bytes.

`customDisplayMessage` uses the public `PassportReaderDisplayMessageHandler` typealias, which is `@Sendable` under Swift 6. Avoid capturing mutable app state in that closure unless the state is actor-isolated or otherwise concurrency-safe.

```swift
let passportReader = PassportReader(masterListURL: masterListURL)

let result = try await passportReader.readPassportIdentity(
    mrzKey: mrzKey,
    options: .notaryStrict,
    progressHandler: { event in
        switch event {
        case .waitingForPassport:
            break
        case .readingDataGroup(let dataGroup, let progress):
            // `dataGroup` is the group name only; `progress` is a 0...1 fraction when available.
            break
        case .complete:
            break
        default:
            break
        }
    },
    customDisplayMessage: { displayMessage in
        switch displayMessage {
        case .requestPresentPassport:
            return "Hold your iPhone near an NFC enabled passport."
        default:
            return nil
        }
    }
)
```

Supported scan profiles are `.identityOnly`, `.identityWithPhoto`, `.fullVerification`, and `.custom([DataGroupId])`.
Prefer the smallest profile that supports the app workflow.
`.fullVerification` reads COM, SOD, DG1, DG2, DG7, DG11, DG12, DG14, and DG15 for identity, photo, signature/mark image, optional personal details, document details, and chip/authentication checks.
Use `photoPolicy: .skip` to remove DG2 from the requested data groups when the app does not need passport face image data.
When a result is projected with `photoPolicy: .skip`, `PassportChipReadResult.faceImageData` is `nil` and `PassportChipReadResult.identity.hasFaceImage` is `false`, even if an internal model already contains DG2, so no-photo result projections do not reveal face-image presence.
When `photoPolicy: .read` remains allowed by the effective `PassportReaderSecurityPolicy`, `PassportChipReadResult.faceImageData` returns the first DG2 face image as explicitly sensitive `PassportChipImageResult` bytes for workflows such as in-app document review. Its format and MIME type are derived from the validated image bytes rather than from possibly inconsistent chip metadata. Treat this value as biometric data: do not log it, attach it to diagnostics, or persist/upload it without a separate app-level privacy decision.

Use `PassportReaderSecurityPolicy` to centralize privacy and verification decisions:

```swift
let result = try await passportReader.readPassportIdentity(
    mrzKey: mrzKey,
    options: .notaryStrict
)
```

Security policies can disallow passport photo reads even when a broader scan profile requests DG2 and require verification strictness such as `.passiveAuthentication`, `.trustedPassiveAuthentication`, or `.fullVerificationWhenSupported`.

`PassportChipReadResult` contains `identity`, optional `faceImageData`, `verificationResult`, `trustLevel`, `certificateTrustMetadata`, and `diagnosticsSummary`. It intentionally does not expose the internal raw model, MRZ text, raw data-group bytes, APDUs, certificates, keys, or active-authentication challenge/signature bytes. It also intentionally does not conform to `Codable`.

`PassportIdentityResult` projects primary names from DG1 MRZ data unless DG11 provides a non-empty ICAO-style full name with the `<<` primary separator. Empty, whitespace-only, or unstructured DG11 names fall back to DG1 instead of replacing a validated MRZ name with blank or ambiguous text. Blank or filler-only DG11 personal-number values likewise fall back to the DG1 optional-data value, and filler-only DG1 optional data is reported as `nil` rather than an empty personal number. Optional DG11 place-of-birth, residence-address, and phone fields are trimmed at projection time; blank or filler-only values are reported as `nil`.

`PassportIdentityResult.dateOfIssue` exposes the normalized DG12 issue date when DG12 is read and the chip provides it. DG1 MRZ birth and expiry dates are rejected unless their `YYMMDD` content has a valid month and day, and DG11 date-of-birth and DG12 issue-date values are rejected unless their `YYYYMMDD` content is a real Gregorian calendar date. This lets apps fill issue-date fields without reopening raw DG12 model access.

`PassportScanOptions` provides reviewed combinations of profile, timeout, photo policy, authentication flags, security policy, and PACE policy. `.notaryStrict` is the recommended starting point for Notary Journal style workflows; `.identityOnly` keeps collection minimal when the app does not need photo or optional verification groups.

PACE policy defaults to `.allowBACFallback` for current passport interoperability. Use `.requirePACEWhenAdvertised` only after validating the target passport population with real devices, and use `.requireExplicitCredential(.can)`, `.pin`, or `.puk` when the workflow has collected that credential and should fail rather than fall back to MRZ-derived PACE/BAC.

If passive authentication runs without a CSCA master list, SOD signature and data-group hash checks can still report that the data groups actually read are internally consistent, but country signer trust is reported as not checked. A trusted signer result requires a master list from the issuing country or ICAO PKD. Certificate revocation is reported separately in `certificateTrustMetadata.revocationCheck`; it remains not checked until a tested CRL/PKD revocation workflow is configured and implemented.

`PassportVerificationResult` keeps the original simple status properties and also includes safe detail fields such as `sodSignatureDetail`, `dataGroupHashDetail`, `countrySigningCertificateDetail`, `activeAuthenticationDetail`, and `chipAuthenticationDetail`. These distinguish cases such as not requested, not supported, skipped, missing SOD, missing master list, signer untrusted, hash mismatch, malformed SOD, unsupported algorithm, attempted failed, and passed without exposing raw hashes or certificate contents. The SOD CMS wrapper, LDS Security Object content type, and data-group hash list are structurally validated before they can drive signature or hash status. `dataGroupCoverage` summarizes whether read groups were covered by SOD hashes.

For support diagnostics, use `PassportReaderDiagnosticsSummary`. It records the scan profile, effective photo policy, effective security policy, safe failure reason, verification summary, trust level, data-group names read, and privacy-safe data-group read reports such as requested, advertised, read, skipped, blocked, unsupported, or failed. Legacy read-all scans preserve requested COM/SOD startup context before COM-advertised groups expand the read set. Final read outcomes replace transient failed/skipped outcomes for the same data group while preserving requested and advertised context. Chip-reported inaccessible or missing optional groups are reported as unsupported after the reader resets BAC for later groups instead of retrying the same group indefinitely. It does not include identity fields, MRZ text, APDUs, certificates, keys, raw data groups, or images.

For private real-device compatibility tracking, use `PassportInteroperabilityRecord` and keep notes non-identifying. It is designed for country/feature-class outcomes, not passport numbers, MRZ text, names, dates of birth, expiration dates, image bytes, APDUs, keys, certificate details, or hex samples. `containsOnlyNonIdentifyingFields` rejects common sensitive labels and byte-pattern notes, but it is a safeguard rather than permission to store detailed scan artifacts.

`PassportReaderPrivacyCopy` provides short suggested consent and diagnostics copy for host apps that want package-owned wording.

Errors can be mapped to privacy-safe app copy and retry decisions:

```swift
do {
    let result = try await passportReader.readPassportIdentity(mrzKey: mrzKey, options: .notaryStrict)
    let verification = result.verificationResult
} catch let error as NFCPassportReaderError {
    let failure = error.privacySafeFailure(at: .readingDataGroup(.DG2))
    // Use failure.reason, failure.stage, failure.isRetryLikelyToHelp, and failure.recoverySuggestion.
}
```

For UI tests or simulator flows, depend on `PassportChipReading` and inject `PassportReaderFixture` instead of creating a real NFC session:

```swift
let fixture = PassportReaderFixture(result: .success(syntheticResult))
```

The reader is scoped to the LDS1 eMRTD application and can read every LDS1 data-group file id. COM, DG1, DG2, DG7, DG11, DG12, DG14, DG15, and SOD have typed parsers used by the safe app-facing result. DG2 preserves multiple biometric templates when present and keeps the first image through the compatibility `imageData` path. DG7 preserves multiple displayed signature/mark image items when present, and empty DG7 placeholders do not count as signature-image presence. DG3, DG4, DG5, DG6, DG8, DG9, DG10, DG13, and DG16 are represented as opaque typed groups internally so they can be read and hashed for passive authentication without public raw export. Optional LDS2 applications, such as travel records, visa records, and additional biometrics, are not implemented by this package.

DG2, DG7, and DG12 image parsing has explicit byte, structure, and image-header bounds. These parsers accept JPEG and JPEG 2000 image payloads with standard headers, including JPEG streams that do not use the JFIF APP0 marker. Malformed payloads with unknown image headers, excessive image bytes, excessive dimensions, or impossible feature-point skips are rejected before unbounded retention or image decoding.

DG11 and DG12 optional text fields are decoded with per-field size bounds, BOM-aware UTF-8/UTF-16 handling, UTF-16 heuristics, and common Latin fallback encodings before using replacement UTF-8. DG12 other-person details are preserved from plain text or nested text TLVs. This preserves more multilingual issuer fields while still avoiding raw byte exposure in public diagnostics or unbounded string retention.

PACE defaults to the MRZ-derived key:

```swift
let result = try await passportReader.readPassportIdentity(
    mrzKey: mrzKey,
    options: .notaryStrict
)
```

If a document or inspection workflow requires a CAN, PIN, or PUK PACE credential, pass it explicitly while still providing the MRZ key for BAC fallback:

```swift
let result = try await passportReader.readPassportIdentity(
    mrzKey: mrzKey,
    scanProfile: .identityWithPhoto,
    paceKey: can,
    paceKeyReference: .can
)
```

Integrated Mapping (IM) is implemented for standardized DH and ECDH domain parameters, with synthetic ICAO Appendix H vector coverage for the IM pseudorandom field mapping and mapped DH/ECDH generators. ECDH Chip Authentication Mapping (CAM) is handled for PACE secure messaging and requires the chip's final CAM data object to be present. EF.CardSecurity is read and parsed when present. If a master list is supplied and EF.CardSecurity CMS verification succeeds against that trust store, trusted EF.CardSecurity chip-authentication public keys can satisfy the CAM proof before DG14 is read. When DG14 is read, the CAM proof is also checked against DG14 chip-authentication public keys and can satisfy chip-authentication status; otherwise the reader falls back to the separate Chip Authentication flow when available. Well-formed but unknown DG14/CardAccess/CardSecurity `SecurityInfo` records are preserved as redacted `UnknownSecurityInfo` values so callers can detect unrecognized security capabilities without exposing raw chip data; malformed `SecurityInfos` wrappers or overlong records fail closed.

Extended mode reads (not supported by all passports) can be enabled through `PassportScanOptions.useExtendedMode`.
This will increase the number of bytes that can be read in a call and may be required for some passports that use long AA keys (some Australian passports for example).

A custom Active Authentication challenge can be provided to `PassportReader` to ensure that the challenge/response was specifically executed in the session and not replayed. Custom challenges must be exactly 8 bytes and malformed custom challenges are rejected before an NFC scan starts. Treat the challenge and signature as sensitive. Do not send active-authentication data, raw chip data, or passport images to a backend unless the host app has explicit user consent, retention rules, transport controls, and a privacy-reviewed validation workflow.

Raw passport dump import/export APIs are not part of this fork's public surface. Low-level NFC, BAC, PACE, secure-messaging, AES/DES/OpenSSL, certificate-wrapper, and raw data-group parser types are module-internal implementation details, not app-level scan APIs. They may process sensitive keys, IVs, APDU payloads, secure-messaging bytes, certificates, hashes, or decrypted chip data. Apps should use `PassportReader.readPassportIdentity(...)` or the safe `PassportChipReading` abstraction rather than constructing NFC, BAC, session-key, cryptographic, certificate, or raw data-group flows directly.


## Logging
Logging is off by default. This fork only exposes privacy-safe, typed reader events; it does not log MRZ values, access keys, APDUs, secure messaging keys, random challenges, decrypted data groups, certificate contents, or passport image bytes.

Reader error `localizedDescription` and default `String(describing:)` output are privacy-safe summaries. Host apps should still prefer `PassportReaderFailure`, `PassportReaderDiagnosticsSummary`, and typed progress/log events for support flows instead of logging raw thrown error values.

You can opt in to redacted high-level events:

```swift
let reader = PassportReader(logLevel: .info)
```

Host apps that need to enforce their own logging policy can provide a sink:

```swift
final class PassportEventSink: PassportReaderLogging {
    func log(_ event: PassportReaderLogEvent) {
        // Store or forward event.description only if it fits your privacy policy.
    }
}

let reader = PassportReader(logLevel: .info, logger: PassportEventSink())
```

Supported levels are `.off`, `.error`, `.info`, and `.debugRedacted`. `.debugRedacted` is intentionally still redacted; this package does not provide a raw byte or key logging mode.

## CI and local verification

Before tagging this fork for app consumption, run:

```bash
scripts/release_check.sh
```

The release check script runs the required iOS package build, iOS build-for-testing, full iOS Simulator test suite, external API surface probe, privacy scan, CoreNFC delegate-boundary check, whitespace check, and a targeted risky diagnostics search. Review any search hits before tagging. Set `IOS_TEST_DESTINATION` if your local simulator name or OS differs from the default.

`swift test` may fail in this environment because SwiftPM evaluates the package against macOS while the OpenSSL dependency requires a newer macOS target. Use the iOS/Xcode path above unless the package manifest is deliberately changed to support macOS tests.

Run at least one manual on-device passport scan before releasing a fork tag, because PACE/BAC/Chip Authentication behavior depends on real chip interoperability.

See `THREAT_MODEL.md` for the fork's privacy and verification assumptions.

## Repository structure

The source tree is organized by responsibility so app integrators can find safe public APIs without digging through low-level NFC or cryptography internals.

- `Sources/NFCPassportReader/API/`: app-facing reader protocols, result types, scan options, policies, and trust labels.
- `Sources/NFCPassportReader/Reader/`: high-level `PassportReader` orchestration and the internal working `NFCPassportModel`.
- `Sources/NFCPassportReader/Diagnostics/`: privacy-safe logging, progress, display messages, failure mapping, scan stages, and support diagnostics.
- `Sources/NFCPassportReader/NFC/`: CoreNFC transport helpers and APDU response handling.
- `Sources/NFCPassportReader/Authentication/`: BAC, PACE, secure messaging, session keys, and chip authentication.
- `Sources/NFCPassportReader/Crypto/`: OpenSSL-facing Swift helpers, X.509, and encryption wrappers.
- `Sources/NFCPassportReader/Verification/`: passive-authentication hashes and structured verification results.
- `Sources/NFCPassportReader/DataGroups/`: LDS data-group models and typed data-group parsing.
- `Sources/NFCPassportReader/Parsing/`: shared TLV, ASN.1, byte, and string parsing helpers.
See `REPOSITORY_STRUCTURE.md` for the full maintainer map, test layout, and guidance on where to start for common changes.

## Other info

### PassiveAuthentication
Passive Authentication is now part of the main library and can be used to ensure that an E-Passport is valid and hasn't been tampered with.

It requires a set of CSCA certificates in PEM format from a master list, either from a country that publishes its master list or from the ICAO PKD repository. See `scripts/README.md` for helper-script notes.

The LDS Security Object hash list is parsed directly from DER, so all DG1-DG16 hash entries can be checked without relying on OpenSSL text-dump formatting. SOD signature verification tries the configured verifier first and then the alternate CMS/manual verifier before falling back to unsigned encapsulated-content extraction for data-group hash comparison. In that fallback case the signature status remains failed while data-group hash status can still report whether the read groups match the SOD. Minimal scan profiles verify the groups they read; they do not prove that unread optional groups match their SOD hashes.

When no master list is supplied, signer-chain trust is not checked rather than failed. Apps should present that as an incomplete trust-anchor configuration, not as evidence that the passport or chip data is bad.

## Troubleshooting
- If authentication fails with `PassportReaderFailure.reason == .accessKeyRejected`, ask the user to re-check the passport number, date of birth, and expiration date used to derive the access key. Some passports use filler characters in the machine-readable zone; host apps should derive the key with a reviewed MRZ helper rather than logging or displaying the derived access key.
- If a scan fails after the phone has already connected to the chip, use the safe retry metadata on `PassportReaderFailure` to decide whether to ask the user to try again. Do not expose low-level status words, APDU bytes, MRZ text, or derived key material in app UI, logs, crash reports, or support diagnostics.

## To do
There are a number of things I'd like to implement in no particular order:
 * Complete real-chip interoperability validation for PACE-GM, PACE-IM, PACE-CAM, EF.CardSecurity trust, DG14 CAM fallback, and multilingual optional fields before broadening release claims.
 

## Thanks
I'd like to thank the writers of pypassport (Jean-Francois Houzard and Olivier Roger - can't find their website but referenced from https://github.com/andrew867/epassportviewer) who's work this is based on.

The EPassport section on YobiWiki (http://wiki.yobi.be/wiki/EPassport)  This has been an invaluable resource especially around Passive Authentication.

Marcin Krzyżanowski for his OpenSSL-Universal repo.
