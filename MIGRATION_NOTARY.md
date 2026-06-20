# Notary Journal Migration Notes

This fork keeps `PassportReader(masterListURL:)` and the existing `readPassport(mrzKey:tags:...)` API source-compatible, but Notary Journal should prefer the newer privacy-safe surfaces.

## Recommended Reader Setup

```swift
let reader = PassportReader(
    masterListURL: Self.masterListURL,
    logLevel: .off
)
```

Logging is off by default. If diagnostics are needed, use `.error` or `.info` with a `PassportReaderLogging` sink that accepts only typed `PassportReaderLogEvent` values.

## Recommended Scan Call

The previous app call requested `.COM`, `.SOD`, `.DG1`, `.DG2`, `.DG12`, `.DG14`, and `.DG15`. In this fork, `.fullVerification` also includes `.DG7` and `.DG11` so Notary Journal can collect signature/mark image presence and optional personal details such as place of birth when the chip provides them. Use a `.custom(...)` profile if the app must preserve the narrower historical collection set.

For new Notary Journal integration work, prefer the reviewed preset and privacy-first return type:

```swift
let result = try await reader.readPassportIdentity(
    mrzKey: mrzKey,
    options: .notaryStrict,
    progressHandler: { event in
        // Map to app UI state. Do not log event values together with identity data.
    },
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

`PassportChipReadResult` exposes normalized identity, verification, trust, certificate/master-list metadata, and safe diagnostics without returning `NFCPassportModel` or raw chip data. It intentionally omits MRZ text, raw data groups, APDUs, certificates, keys, active-authentication challenge/signature bytes, and image bytes.

If the app still needs transient photo review from `NFCPassportModel.passportImage`, use the compatibility call below and call `passport.removeSensitiveDataForPrivacy()` as soon as the app has projected identity fields, verification status, and any in-memory photo review object it deliberately needs.

```swift
let passport = try await reader.readPassport(
    mrzKey: mrzKey,
    scanProfile: .fullVerification,
    skipSecureElements: true,
    skipCA: false,
    skipPACE: false,
    useExtendedMode: true,
    operationTimeout: 60,
    photoPolicy: .read,
    securityPolicy: .notaryRecommended,
    progressHandler: { event in
        // Map to app UI state. Do not log event values together with identity data.
    },
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

Use `.identityOnly` or `.identityWithPhoto` only after confirming Notary Journal does not need optional details, signature/mark images, or chip-authentication groups for its workflow.
For compatibility calls that still use `readPassport(mrzKey:tags:)`, an empty tag list plus `securityPolicy: .identityOnly` now resolves to the minimal identity group set instead of reading every group advertised by COM.

`PassportReaderSecurityPolicy.notaryRecommended` currently allows passport photo review, blocks unsafe raw export, and requires passive-authentication integrity checks to pass when verification is attempted. If Notary Journal needs a softer rollout while validating real passports, use `.default` temporarily and document the reason in this file before tagging.

`PassportScanOptions.notaryStrict` uses the compatibility PACE policy `.allowBACFallback` so existing MRZ-based scans still work while Notary validates its passport population. After real-device coverage confirms the rollout path, the app can choose `.requirePACEWhenAdvertised` or `.requireExplicitCredential(.can)` for workflows where fallback should be blocked.

Prefer `passport.identityResult` for app-facing mapping where possible. It omits MRZ text, raw data-group bytes, APDU data, certificates, cryptographic material, and image bytes while preserving normalized fields, verification status, trust level, and certificate-trust metadata. Passive authentication verifies the groups that were actually read; app copy should not imply unread optional groups were checked.

Use `passport.verificationResult.*Detail` fields when the app needs to distinguish missing master list, skipped authentication, unsupported authentication, hash mismatch, signer trust failure, and other safe reasons. Do not parse raw error strings.

Use `PassportReaderDiagnosticsSummary` for support flows that need safe scan metadata, including data-group read reports that say whether a group was requested, advertised, read, skipped, blocked, unsupported, or failed. Do not attach raw model dumps, screenshots of identity fields, console logs, or passport photos to support diagnostics.

For private interoperability tracking, use `PassportInteroperabilityRecord` with non-identifying country/feature-class outcomes only. Do not store MRZ text, document numbers, exact dates, images, APDUs, keys, certificate dumps, or long hex samples in compatibility notes.

## Failure Handling

```swift
catch let error as NFCPassportReaderError {
    let failure = error.privacySafeFailure(at: .unknown)
    // Use failure.reason, failure.stage, failure.isRetryLikelyToHelp, and failure.recoverySuggestion.
}
```

Do not display or log `error.value`; it is retained only for internal compatibility paths.

## Test Injection

Depend on `PassportChipReading` in app services and inject `PassportReaderFixture` in simulator and UI tests. This allows success and failure flows without NFC hardware or real passport data.

## Sensitive Export API

`NFCPassportModel.dumpPassportData(...)` is deprecated in this fork because it returns raw Base64-encoded chip data. Notary Journal should use `identityResult`, `verificationResult`, and app-owned in-memory photo review data instead. Raw export should remain unused; if a future workflow truly requires it, use `UnsafePassportRawDataExporter` only with explicit user consent, written retention rules, and `PassportReaderSecurityPolicy(allowsUnsafeRawDataExport: true)`.

Legacy `NFCPassportModel(from:)` raw-dump import now records sanitized `rawDataImportErrors` for malformed entries. Notary Journal should not use raw dump import in normal scan flows, but any migration or support tooling that does use it should check this property before trusting the rebuilt model.

Do not use low-level BAC/session-key APIs from app code. This fork keeps BAC key material internal to the reader flow; Notary Journal should depend on `PassportReader` or `PassportChipReading` only.

## Release Checklist

- Build this package with the iOS package scheme.
- Build Notary Journal against the fork tag.
- Run `scripts/release_check.sh` in the fork.
- Run an on-device passport scan.
- Validate `.notaryStrict` against real passports before making it mandatory in production, especially when the master list is absent or incomplete.
- Confirm Xcode console output contains no MRZ/access-key/APDU/key/data-group/photo byte dumps.
