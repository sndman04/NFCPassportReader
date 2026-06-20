# Notary Journal Migration Notes

This fork intentionally exposes the privacy-safe passport-chip API as the app integration boundary. Notary Journal should use `readPassportIdentity(...)` and should not depend on the internal raw passport model.

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

Use `.identityOnly` or `.identityWithPhoto` only after confirming Notary Journal does not need optional details, signature/mark images, or chip-authentication groups for its workflow.

`PassportReaderSecurityPolicy.notaryRecommended` currently allows passport photo presence in the safe result and requires passive-authentication integrity checks to pass when verification is attempted. If Notary Journal needs a softer rollout while validating real passports, use `.default` temporarily and document the reason in this file before tagging.

`PassportScanOptions.notaryStrict` uses `.allowBACFallback` for current passport interoperability while Notary validates its passport population. After real-device coverage confirms the rollout path, the app can choose `.requirePACEWhenAdvertised` or `.requireExplicitCredential(.can)` for workflows where fallback should be blocked.

Use `result.identity`, `result.verificationResult`, `result.trustLevel`, and `result.certificateTrustMetadata` for app-facing mapping. Passive authentication verifies the groups that were actually read; app copy should not imply unread optional groups were checked.

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

Do not display or log `error.value`; use `privacySafeFailure` or `privacySafeFailure(at:)` instead.

## Test Injection

Depend on `PassportChipReading` in app services and inject `PassportReaderFixture` in simulator and UI tests. This allows success and failure flows without NFC hardware or real passport data.

## Raw Data Boundary

Raw passport dump import/export APIs are not public in this fork. Notary Journal should use the projected `PassportChipReadResult` only and should not add support tooling that stores raw data groups, APDUs, active-authentication challenge/signature bytes, certificate dumps, or passport image bytes.

Do not use low-level BAC/session-key APIs from app code. This fork keeps BAC key material internal to the reader flow; Notary Journal should depend on `PassportReader` or `PassportChipReading` only.

## Release Checklist

- Build this package with the iOS package scheme.
- Build Notary Journal against the fork tag.
- Run `scripts/release_check.sh` in the fork.
- Run an on-device passport scan.
- Validate `.notaryStrict` against real passports before making it mandatory in production, especially when the master list is absent or incomplete.
- Confirm Xcode console output contains no MRZ/access-key/APDU/key/data-group/photo byte dumps.
