# NFCPassportReader

This package handles reading an NFC Enabled passport using iOS 15 CoreNFC APIS

**Version 2 (and the main branch) now uses Swift Async/Await for communication.  If you need an earlier version, please use 1.1.9 or below!**

Supported features:
* Basic Access Control (BAC)
* Secure Messaging
* Reads and preserves all LDS data groups. COM, DG1, DG2, DG7, DG11, DG12, DG14, DG15, and SOD have typed parsers; DG3, DG4, DG5, DG6, DG8, DG9, DG10, DG13, and DG16 are retained as opaque typed data groups for hashing and explicit raw export workflows.
* Passive Authentication with structured LDS Security Object hash parsing and CMS verification fallback.
* Active Authentication with RSA and ECDSA DG15 public-key detection.
* Chip Authentication (ECDH DES and AES keys tested, DH DES AES keys implemented ad should work but currently not tested)
* PACE with MRZ, CAN, PIN, or PUK password references. When a chip advertises multiple PACE options, implemented Generic Mapping (GM) options are used when available. Integrated Mapping (IM) and Chip Authentication Mapping (CAM) remain explicit unsupported paths.
* Ability to dump passport stream and read it back in
* Uses Async/Await

This is still very early days - the code is by no means perfect and there are still some rough edges  - there ARE most definitely bugs and I'm sure I'm not doing things perfectly. 

It reads and verifies my passport (and others I've been able to test) fine, however your mileage may vary.

## Installation
### Swift Package Manager (recommended)

NFCPassportReader may be installed via Swift Package Manager, by pointing to this repo's URL.

## Privacy-safe fork usage

This fork is intended for apps that need passport chip reading without leaking identity-document data through logs, diagnostics, or broad raw-data APIs. Logging is off by default, and opt-in logging is typed and redacted.

Create the Passport MRZ key in app memory from the passport number, date of birth, and expiry date, including their checksums. Dates are in YYMMDD format. Treat the resulting access key as sensitive: do not log, persist, upload, or include it in bug reports.

For example:

```
<passport number><passport number checksum><date of birth><date of birth checksum><expiry date><expiry date checksum>

e.g. for Passport nr 12345678, Date of birth 27-Jan-1998, Expiry 30-Aug-2025 the MRZ Key would be:

Passport number - 12345678
Passport number checksum - 8
Date Of birth - 980127
Date of birth checksum - 7
Expiry date - 250830
Expiry date checksum - 5

mrzKey = "12345678898012772508315"
```

Then create a `PassportReader` and call the async `readPassport` API. Prefer scan profiles over ad hoc data-group lists where possible.

Progress events are structured and redacted; they do not include MRZ values, APDUs, keys, decrypted data groups, or image bytes.

```swift
let passportReader = PassportReader(masterListURL: masterListURL)

let passport = try await passportReader.readPassport(
    mrzKey: mrzKey,
    scanProfile: .identityWithPhoto,
    operationTimeout: 60,
    photoPolicy: .read,
    securityPolicy: .default,
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
Use `photoPolicy: .skip` to remove DG2 from the requested data groups when the app does not need passport face image data. The policy is also applied after COM expansion for legacy empty-tag reads.

Use `PassportReaderSecurityPolicy` to centralize privacy and verification decisions:

```swift
let passport = try await passportReader.readPassport(
    mrzKey: mrzKey,
    scanProfile: .fullVerification,
    photoPolicy: .read,
    securityPolicy: .notaryRecommended
)
```

Security policies can disallow passport photo reads even when a broader scan profile requests DG2, block raw export by default, and require verification strictness such as `.passiveAuthentication`, `.trustedPassiveAuthentication`, or `.fullVerificationWhenSupported`.
For legacy `readPassport(mrzKey:tags:)` calls that pass an empty tag list, `securityPolicy: .identityOnly` resolves to the minimal identity profile instead of expanding to every group advertised by COM.

For app-facing data, prefer `passport.identityResult`. It contains normalized identity fields, verification status, trust level, and certificate-trust metadata, and intentionally omits MRZ text, raw data-group bytes, APDUs, certificates, keys, and image bytes.

If passive authentication runs without a CSCA master list, SOD signature and data-group hash checks can still report that the data groups actually read are internally consistent, but country signer trust is reported as not checked. A trusted signer result requires a master list from the issuing country or ICAO PKD.

For support diagnostics, use `PassportReaderDiagnosticsSummary`. It records the scan profile, photo policy, security policy, safe failure reason, verification summary, trust level, and data-group names read. It does not include identity fields, MRZ text, APDUs, certificates, keys, raw data groups, or images.

`PassportReaderPrivacyCopy` provides short suggested consent and diagnostics copy for host apps that want package-owned wording.

Errors can be mapped to privacy-safe app copy and retry decisions:

```swift
do {
    let passport = try await passportReader.readPassport(mrzKey: mrzKey, scanProfile: .fullVerification)
    let verification = passport.verificationResult
} catch let error as NFCPassportReaderError {
    let failure = error.privacySafeFailure
    // Use failure.reason, failure.isRetryLikelyToHelp, and failure.recoverySuggestion.
}
```

For UI tests or simulator flows, depend on `PassportChipReading` and inject `PassportReaderFixture` instead of creating a real NFC session:

```swift
let fixture = PassportReaderFixture(result: .success(NFCPassportModel()))
```

The reader can read every LDS data-group file id. COM, DG1, DG2, DG7, DG11, DG12, DG14, DG15, and SOD have typed parsers used by the app-facing model. DG7 preserves multiple displayed signature/mark image items when present while keeping the first image available through the existing compatibility API. DG3, DG4, DG5, DG6, DG8, DG9, DG10, DG13, and DG16 are represented as opaque typed groups so they can be read, retained, hashed for passive authentication, and exported only through explicit unsafe raw-export policy.

PACE defaults to the MRZ-derived key:

```swift
let passport = try await passportReader.readPassport(
    mrzKey: mrzKey,
    scanProfile: .fullVerification
)
```

If a document or inspection workflow requires a CAN, PIN, or PUK PACE credential, pass it explicitly while still providing the MRZ key for BAC fallback:

```swift
let passport = try await passportReader.readPassport(
    mrzKey: mrzKey,
    scanProfile: .identityWithPhoto,
    paceKey: can,
    paceKeyReference: .can
)
```

Integrated Mapping (IM) and Chip Authentication Mapping (CAM) are not silently treated as supported. They fail with a privacy-safe PACE failure until implemented and validated against real chips. Unknown DG14/CardAccess `SecurityInfo` records are preserved as redacted `UnknownSecurityInfo` values so callers can detect unrecognized security capabilities without exposing raw chip data.

Extended mode reads (not supported by all passports) can be enabled by passing in the useExtendedMode flag to the readPassport function.
This will increase the number of bytes that can be read in a call and may be required for some passports that use long AA keys (some Australian passports for example).

A custom Active Authentiion challenge can be provided to the PassportReader to ensure that the challenge/response was specifically executed in the session and not replayed. The app could then send the activeAuthenticationSignature to a backend, along with the rest of the chip data to perform validation.

`NFCPassportModel.dumpPassportData(...)` is deprecated in this fork because it returns raw Base64-encoded passport chip data. Prefer `identityResult`, `verificationResult`, and privacy-safe failure/progress diagnostics. Rare raw export workflows should use `UnsafePassportRawDataExporter` with a `PassportReaderSecurityPolicy` that explicitly sets `allowsUnsafeRawDataExport: true`.


## Logging
Logging is off by default. This fork only exposes privacy-safe, typed reader events; it does not log MRZ values, access keys, APDUs, secure messaging keys, random challenges, decrypted data groups, certificate contents, or passport image bytes.

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
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build-for-testing
scripts/privacy_scan.sh
git diff --check
```

`swift test` may fail in this environment because SwiftPM evaluates the package against macOS while the OpenSSL dependency requires a newer macOS target. Use the iOS/Xcode path above unless the package manifest is deliberately changed to support macOS tests.

Run at least one manual on-device passport scan before releasing a fork tag, because PACE/BAC/Chip Authentication behavior depends on real chip interoperability.

See `THREAT_MODEL.md` for the fork's privacy and verification assumptions.

## Other info

### PassiveAuthentication
Passive Authentication is now part of the main library and can be used to ensure that an E-Passport is valid and hasn't been tampered with.

It requires a set of CSCA certificates in PEM format from a master list, either from a country that publishes its master list or from the ICAO PKD repository. See `scripts/README.md` for helper-script notes.

The LDS Security Object hash list is parsed directly from DER, so all DG1-DG16 hash entries can be checked without relying on OpenSSL text-dump formatting. SOD signature verification tries the configured verifier first and then the alternate CMS/manual verifier before falling back to unsigned encapsulated-content extraction for data-group hash comparison. In that fallback case the signature status remains failed while data-group hash status can still report whether the read groups match the SOD. Minimal scan profiles verify the groups they read; they do not prove that unread optional groups match their SOD hashes.

When no master list is supplied, signer-chain trust is not checked rather than failed. Apps should present that as an incomplete trust-anchor configuration, not as evidence that the passport or chip data is bad.

## Troubleshooting
* If when doing the initial Mutual Authenticate challenge, you get an error with and SW1 code 0x63, SW2 code 0x00, reason: No information given, then this is usualy because your MRZ key is incorrect, and possibly because your passport number is not quite right.  If your passport number in the MRZ contains a '<' then you need to include this in the MRZKey - the checksum should work out correct too.  For more details, check out App-D2 in the ICAO 9303 Part 11 document (https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)
<br><br>e.g. if the bottom line on the MRZ looks like:
12345678<8AUT7005233M2507237<<<<<<<<<<<<<<06
<br><br>
In this case the passport number is 12345678 but is padded out with an additonal <. This needs to be included in the MRZ key used for BAC.
e.g. 12345678<870052332507237 would be the key used.



## To do
There are a number of things I'd like to implement in no particular order:
 * Finish off PACE authentication for Integrated Mapping (IM) and Chip Authentication Mapping (CAM), with real-chip interoperability validation.
 

## Thanks
I'd like to thank the writers of pypassport (Jean-Francois Houzard and Olivier Roger - can't find their website but referenced from https://github.com/andrew867/epassportviewer) who's work this is based on.

The EPassport section on YobiWiki (http://wiki.yobi.be/wiki/EPassport)  This has been an invaluable resource especially around Passive Authentication.

Marcin Krzyżanowski for his OpenSSL-Universal repo.
