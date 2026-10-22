# Notary Journal Migration Notes

This fork intentionally exposes the privacy-safe passport-chip API as the app integration boundary. Notary Journal should use `readPassportIdentity(...)` and should not depend on the internal raw passport model.

The fork now requires SwiftPM tools 6.3, Swift 6 language mode, Xcode 26.5 or newer, and iOS 26.0 or newer. This matches the app-only integration plan and intentionally drops older-package consumer compatibility.

## PACE-to-BAC recovery (after privacy.5)

Compatibility reference: `d31fefb50d158f69918fb8bb028d9ad46693e01b` (`notary-2.3.1-privacy.5`). The `readPassportIdentity` call using `skipPACE: false` and default `.allowBACFallback` needs no argument changes. Pin the new dependency commit/candidate tag; this change does not edit the consuming app.

- Failed PACE now releases local authentication state and, after chip-side PACE initialization, obtains a fresh tag activation via polling restart. An unavailable EF.CardAccess/PACE implementation instead restores the passport application directly when possible.
- A rejected application selection gets one fresh-connection retry. No PACE attempt is repeated. There are at most two polling restarts, within the original NFC session and scan deadline. No new NFC sheet is opened automatically.
- `.paceFailedFallbackToBAC` means preparation has begun, and its stage is now `.bacFallbackPreparation`. Show access-key checking only after `.bacStarted`.
- Handle the additive error `.BACFallbackPreparationFailed`, failure reason `.bacFallbackPreparationFailed`, and scan stage `.bacFallbackPreparation` in exhaustive switches. Use the supplied safe message/recovery suggestion; do not ask users to correct their MRZ for a preparation failure. Existing connection-loss, timeout, cancellation, and BAC access-key failures retain their meanings.
- PACE-required policies also prohibit BAC reauthentication during later read/authentication recovery. Successful initial PACE and the explicit `skipPACE` BAC path retain their intended behavior.
- This is a candidate for on-device verification. Before production rollout, test successful PACE, BAC-only documents, interrupted PACE chains, fallback selection recovery, wrong access details, cancellation, and timeout with non-identifying outcome records. Synthetic tests cannot prove issuer-specific RF reset behavior; if reactivation cannot restore the app, the bounded failure instructs a new scan after removing the passport.

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
            return "Start with the top of your iPhone against the passport's rear cover. Move it slowly until it connects, then hold it still."
        case .successfulRead:
            return "Passport chip read."
        default:
            return nil
        }
    }
)
```

`customDisplayMessage` is now `PassportReaderDisplayMessageHandler`, an `@Sendable` closure. Keep captured UI or model state main-actor isolated, or capture immutable values only.

`PassportChipReadResult` exposes normalized identity, optional `faceImageData`, verification, trust, certificate/master-list metadata, and safe diagnostics without returning `NFCPassportModel` or raw chip data. It intentionally omits MRZ text, raw data groups, APDUs, certificates, keys, and active-authentication challenge/signature bytes.

Use `result.faceImageData` only when Notary Journal's review workflow needs the chip photo. It is populated only when the effective photo policy is `.read`, such as `.notaryStrict` with `PassportReaderSecurityPolicy.notaryRecommended`. Treat it as sensitive biometric data: keep it transient, do not log it, and do not include it in support diagnostics.

Use `result.identity.dateOfIssue` for DG12 issue-date autofill. This replaces the old app-side dependency on raw `DataGroup12`.

Use `.identityOnly` or `.identityWithPhoto` only after confirming Notary Journal does not need optional details, signature/mark images, or chip-authentication groups for its workflow.

`PassportReaderSecurityPolicy.notaryRecommended` currently allows passport photo presence in the safe result and requires passive-authentication integrity checks to pass when verification is attempted. If Notary Journal needs a softer rollout while validating real passports, use `.default` temporarily and document the reason in this file before tagging.

`PassportScanOptions.notaryStrict` uses `.allowBACFallback`, short-length NFC commands, and a 90-second operation timeout for current passport interoperability while Notary validates its passport population. Some chips reject extended-length commands even though their data is otherwise readable. After real-device coverage confirms the rollout path, the app can choose `.requirePACEWhenAdvertised`, `.requireExplicitCredential(.can)`, or a custom extended-mode option for workflows and passport populations where those choices have been validated.

When Notary requires passive authentication but does not require Chip or Active Authentication, it may use a custom profile containing `.COM`, `.SOD`, `.DG1`, and only the app-visible optional groups it needs. Omitting DG14/DG15 avoids invoking optional authentication on chips that advertise those files but reject the corresponding command flow. Optional image/parser incompatibility can produce a successful result without `faceImageData`; keep the existing visual/manual fallback available when the photo is absent.

Use `result.identity`, `result.verificationResult`, `result.trustLevel`, and `result.certificateTrustMetadata` for app-facing mapping. Passive authentication verifies the groups that were actually read; app copy should not imply unread optional groups were checked.

Use `passport.verificationResult.*Detail` fields when the app needs to distinguish missing master list, skipped authentication, unsupported authentication, hash mismatch, signer trust failure, and other safe reasons. Do not parse raw error strings.

Use `PassportReaderDiagnosticsSummary` for support flows that need safe scan metadata, including data-group read reports that say whether a group was requested, advertised, read, skipped, blocked, unsupported, or failed. Do not attach raw model dumps, screenshots of identity fields, console logs, or passport photos to support diagnostics.

For private interoperability tracking, use `PassportInteroperabilityRecord` with non-identifying country/feature-class outcomes only. Do not store MRZ text, document numbers, exact dates, images, APDUs, keys, certificate dumps, or long hex samples in compatibility notes.

## Failure Handling

```swift
catch let error as NFCPassportReaderError {
    let failure = reader.privacySafeFailure(for: error)
    // Show failure.userMessage followed by failure.recoverySuggestion.
    // failure.stage and failure.verificationReason are safe typed support context.
}
```

Do not display or log `error.value`. Prefer `reader.privacySafeFailure(for:)` after a scan so the failure includes the captured stage and safe verification category. The error-only `privacySafeFailure` and `privacySafeFailure(at:)` mappings remain available when no reader instance is in scope.

## Test Injection

Depend on `PassportChipReading` in app services and inject `PassportReaderFixture` in simulator and UI tests. This allows success and failure flows without NFC hardware or real passport data.

## Raw Data Boundary

Raw passport dump import/export APIs are not public in this fork. Notary Journal should use the projected `PassportChipReadResult` only and should not add support tooling that stores raw data groups, APDUs, active-authentication challenge/signature bytes, certificate dumps, or passport image bytes outside the deliberately requested transient `faceImageData` review path.

Do not use low-level BAC/session-key APIs from app code. This fork keeps BAC key material internal to the reader flow; Notary Journal should depend on `PassportReader` or `PassportChipReading` only.

## Release Checklist

- Build this package with the iOS package scheme.
- Build Notary Journal against the fork tag.
- Run `scripts/release_check.sh` in the fork.
- Run an on-device passport scan.
- Validate `.notaryStrict` against real passports before making it mandatory in production, especially when the master list is absent or incomplete.
- Confirm Xcode console output contains no MRZ/access-key/APDU/key/data-group/photo byte dumps.
