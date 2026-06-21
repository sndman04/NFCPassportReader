# Repository Structure

This fork is organized around the responsibilities of an iOS passport-chip reader. The folder names are intended to help app developers find safe public APIs quickly while keeping low-level NFC, cryptography, and parsing internals easy to audit.

## Top Level

- `Package.swift`: Swift Package Manager manifest for the `NFCPassportReader` library, the `OpenSSLCompat` C shim, and package tests.
- `Sources/`: Library source code.
- `Tests/`: XCTest coverage for parsing, diagnostics, privacy behavior, crypto helpers, and reader policies.
- `scripts/`: Local maintenance scripts, including privacy and release checks.
- `.github/workflows/`: iOS package CI workflow.
- `readme.md`: User-facing package usage, privacy guidance, and release checklist.
- `MIGRATION_NOTARY.md`: Notary Journal integration and migration notes.
- `THREAT_MODEL.md`: Privacy and security assumptions for this fork.
- `NFCPASSPORTREADER_FORK_SECURITY_AND_FUNCTIONALITY_PLAN.md`: Source of truth for fork priorities, implementation status, verification, and remaining work.

## Branch And Release Policy

- `main`: maintained Notary/privacy release line. It should build, pass the release checks before release tagging, and expose the documented privacy-safe app API.
- `notary-*` tags: annotated app-consumption tags. Notary Journal should pin these rather than a moving branch.
- `upstream/*`: preserved upstream snapshots used for comparison and future update planning. These branches are not app-compatible unless the Notary/privacy changes have been merged and verified.
- Temporary work branches may exist during development, but completed release work should land on `main` and be represented by an annotated tag.

## Main Library Target

All Swift files under `Sources/NFCPassportReader/` compile into the single `NFCPassportReader` module. Subfolders are for maintainability and auditability; they do not create separate Swift modules.

- `API/`: Public, app-facing types and policies. Start here for host-app integration. Examples include `PassportChipReading`, `PassportChipReadResult`, `PassportIdentityResult`, scan profiles/options, photo policy, PACE key references, security policy, data-group read policy, and trust labels.
- `Reader/`: High-level reader orchestration and the internal passport working model. `PassportReader` owns the CoreNFC read flow, while `NFCPassportModel` remains an internal implementation detail for parsing, verification, and safe result projection.
- `Diagnostics/`: Privacy-safe logging, progress, display messages, failure mapping, scan stages, data-group read reports, and private interoperability records. This folder should never expose raw MRZ text, APDUs, key material, decrypted data groups, certificate dumps, or image bytes.
- `NFC/`: Low-level NFC transport helpers such as APDU response handling and tag reads.
- `Authentication/`: BAC, PACE, secure messaging, session-key generation, and chip-authentication flows.
- `Crypto/`: OpenSSL-facing Swift helpers, X.509 wrapper code, and symmetric encryption wrappers.
- `Verification/`: Passive-authentication hash data and structured verification result/detail types.
- `DataGroups/`: LDS data-group models and typed parsers for COM, SOD, DG1, DG2, DG7, DG11, DG12, DG14, DG15, opaque groups, and security-info records.
- `Parsing/`: Shared TLV/ASN.1/string/byte parsing utilities and the data-group parser dispatcher.
- `Models/`: Supporting value models shared by parser and app-facing output code.
- `Privacy/`: Privacy-safe host-app copy and wording helpers.
- `Unsafe/`: Reserved quarantine folder for any deliberately unsafe compatibility surface. It is expected to stay empty unless an unsafe API is explicitly reintroduced with plan updates, docs, tests, and policy gates.
- `Resources/`: Package resources such as `PrivacyInfo.xcprivacy`.

## OpenSSL Compatibility Target

- `Sources/OpenSSLCompat/`: Small C compatibility boundary around OpenSSL APIs used by the Swift target.
- `Sources/OpenSSLCompat/include/`: Public C headers for the compatibility target.

## Tests

Tests mirror the source responsibilities where practical:

- `Tests/NFCPassportReaderTests/Core/`: General helpers, byte utilities, crypto wrapper behavior, secure messaging, and reader-adjacent regressions.
- `Tests/NFCPassportReaderTests/Diagnostics/`: Privacy-safe logging, progress descriptions, error mapping, scan policies, diagnostics, and API behavior.
- `Tests/NFCPassportReaderTests/Parsing/`: Data-group parsing, malformed TLV/ASN.1 handling, image bounds, SOD/security-info parsing, and parser hardening.

Use synthetic fixtures only. Do not add real passport values, MRZ strings, APDU captures, certificate dumps, passport photo bytes, or chip logs.

## Where To Start

- Building an app integration: start with `Sources/NFCPassportReader/API/` and the "Privacy-safe fork usage" section in `readme.md`.
- Changing the NFC scan flow: inspect `Sources/NFCPassportReader/Reader/`, then `NFC/`, `Authentication/`, and `Diagnostics/`.
- Changing CoreNFC session creation: keep construction centralized in `Sources/NFCPassportReader/NFC/PassportNFCSessionFactory.swift` and run `scripts/nfc_boundary_check.sh`.
- Changing verification or trust semantics: inspect `Verification/`, `DataGroups/SOD.swift`, `Crypto/`, and the relevant tests.
- Changing parsing: inspect `DataGroups/`, `Parsing/`, and `Tests/NFCPassportReaderTests/Parsing/`.
- Changing logging, user-facing errors, progress, or support diagnostics: inspect `Diagnostics/` and run `scripts/privacy_scan.sh` before handoff.
- Touching raw data lifetime behavior: inspect `Reader/NFCPassportModel.swift`, privacy/security-policy tests, and update migration notes if public behavior changes.

## Verification After Structural Changes

After moving files or changing folder boundaries, run:

```sh
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
scripts/privacy_scan.sh
git diff --check
```

For release-bound work, run the consolidated script:

```sh
scripts/release_check.sh
```
