# NFCPassportReader

This package handles reading an NFC Enabled passport using iOS 15 CoreNFC APIS

**Version 2 (and the main branch) now uses Swift Async/Await for communication.  If you need an earlier version, please use 1.1.9 or below!**

Supported features:
* Basic Access Control (BAC)
* Secure Messaging
* Reads DG1 (MRZ data) and DG2 (Image) in both JPEG and JPEG2000 formats, DG7, DG11, DG12, DG14 and DG15 (also SOD and COM datagroups)
* Passive Authentication
* Active Authentication
* Chip Authentication (ECDH DES and AES keys tested, DH DES AES keys implemented ad should work but currently not tested)
* PACE - currently only Generic Mapping (GM) supported
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
Use `photoPolicy: .skip` to remove DG2 from the requested data groups when the app does not need passport face image data.

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

Currently supported data groups are COM, DG1, DG2, DG7, DG11, DG12, DG14 (partial), DG15, and SOD.

Extended mode reads (not supported by all passports) can be enabled by passing in the useExtendedMode flag to the readPassport function.
This will increase the number of bytes that can be read in a call and may be required for some passports that use long AA keys (some Australian passports for example).

A custom Active Authentiion challenge can be provided to the PassportReader to ensure that the challenge/response was specifically executed in the session and not replayed. The app could then send the activeAuthenticationSignature to a backend, along with the rest of the chip data to perform validation.

`NFCPassportModel.dumpPassportData(...)` is deprecated in this fork because it returns raw Base64-encoded passport chip data. Prefer normalized model fields, `verificationResult`, and privacy-safe failure/progress diagnostics.


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

## Other info

### PassiveAuthentication
Passive Authentication is now part of the main library and can be used to ensure that an E-Passport is valid and hasn't been tampered with.

It requires a set of CSCA certificates in PEM format from a master list, either from a country that publishes its master list or from the ICAO PKD repository. See `scripts/README.md` for helper-script notes.

## Troubleshooting
* If when doing the initial Mutual Authenticate challenge, you get an error with and SW1 code 0x63, SW2 code 0x00, reason: No information given, then this is usualy because your MRZ key is incorrect, and possibly because your passport number is not quite right.  If your passport number in the MRZ contains a '<' then you need to include this in the MRZKey - the checksum should work out correct too.  For more details, check out App-D2 in the ICAO 9303 Part 11 document (https://www.icao.int/publications/Documents/9303_p11_cons_en.pdf)
<br><br>e.g. if the bottom line on the MRZ looks like:
12345678<8AUT7005233M2507237<<<<<<<<<<<<<<06
<br><br>
In this case the passport number is 12345678 but is padded out with an additonal <. This needs to be included in the MRZ key used for BAC.
e.g. 12345678<870052332507237 would be the key used.



## To do
There are a number of things I'd like to implement in no particular order:
 * Finish off PACE authentication (IM and CAM)
 

## Thanks
I'd like to thank the writers of pypassport (Jean-Francois Houzard and Olivier Roger - can't find their website but referenced from https://github.com/andrew867/epassportviewer) who's work this is based on.

The EPassport section on YobiWiki (http://wiki.yobi.be/wiki/EPassport)  This has been an invaluable resource especially around Passive Authentication.

Marcin Krzyżanowski for his OpenSSL-Universal repo.
