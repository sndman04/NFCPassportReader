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

The current app requests `.COM`, `.SOD`, `.DG1`, `.DG2`, `.DG12`, `.DG14`, and `.DG15`, which maps to `.fullVerification`.

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

Use `.identityOnly` or `.identityWithPhoto` only after confirming Notary Journal does not need optional details or chip-authentication groups for its workflow.

`PassportReaderSecurityPolicy.notaryRecommended` currently allows passport photo review, blocks unsafe raw export, and requires passive-authentication integrity checks to pass when verification is attempted. If Notary Journal needs a softer rollout while validating real passports, use `.default` temporarily and document the reason in this file before tagging.

Prefer `passport.identityResult` for app-facing mapping where possible. It omits MRZ text, raw data-group bytes, APDU data, certificates, cryptographic material, and image bytes while preserving normalized fields, verification status, trust level, and certificate-trust metadata.

Use `PassportReaderDiagnosticsSummary` for support flows that need safe scan metadata. Do not attach raw model dumps, screenshots of identity fields, console logs, or passport photos to support diagnostics.

## Failure Handling

```swift
catch let error as NFCPassportReaderError {
    let failure = error.privacySafeFailure
    // Use failure.reason, failure.isRetryLikelyToHelp, and failure.recoverySuggestion.
}
```

Do not display or log `error.value`; it is retained only for internal compatibility paths.

## Test Injection

Depend on `PassportChipReading` in app services and inject `PassportReaderFixture` in simulator and UI tests. This allows success and failure flows without NFC hardware or real passport data.

## Sensitive Export API

`NFCPassportModel.dumpPassportData(...)` is deprecated in this fork because it returns raw Base64-encoded chip data. Notary Journal should use `identityResult`, `verificationResult`, and app-owned in-memory photo review data instead. Raw export should remain unused; if a future workflow truly requires it, use `UnsafePassportRawDataExporter` only with explicit user consent, written retention rules, and `PassportReaderSecurityPolicy(allowsUnsafeRawDataExport: true)`.

## Release Checklist

- Build this package with the iOS package scheme.
- Build Notary Journal against the fork tag.
- Run the local privacy scan with `scripts/privacy_scan.sh`.
- Run an on-device passport scan.
- Confirm Xcode console output contains no MRZ/access-key/APDU/key/data-group/photo byte dumps.
