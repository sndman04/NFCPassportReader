# Privacy-safe scan diagnostics — schema 1

`PassportDiagnosticSnapshot` is an immutable `Sendable`, `Equatable`, `Encodable` value. It records observed evidence before the working passport model is scrubbed, including failed scans. It contains no identity fields, raw document data, cryptographic material, free-form messages, or underlying errors. It does not change scan acceptance, retry policy, verifier order, or fallback behavior.

## Integration

Existing `readPassportIdentity`, `PassportChipReading`, typed errors, progress events, logger events and defaults remain compatible. The additive initializer parameter is optional:

```swift
@MainActor
func scan(accessKey: String, logger: any PassportReaderLogging,
          receiveDiagnostic: @escaping PassportDiagnosticHandler) async throws -> PassportChipReadResult {
    let reader = PassportReader(
        logLevel: .info,
        logger: logger,
        diagnosticHandler: receiveDiagnostic
    )
    // receiveDiagnostic receives exactly one snapshot on success or failure.
    // Forward it to the app's existing diagnostic store, separately from identity data.
    return try await reader.readPassportIdentity(mrzKey: accessKey, options: .notaryStrict)
}
```

A supplied custom logger continues to receive the existing typed high-level events. `logLevel` still defaults to `.off`; a custom sink prevents creation of the console sink. The diagnostic handler is independent of log level and has no built-in console output or persistence. An existing logger can own a separate `record(snapshot:)` method and receive snapshots through this closure. Do not stringify the returned identity result or the thrown legacy error's associated payloads.

Additional access:

- `reader.lastDiagnosticSnapshot`: the latest completed attempt, available in `catch` and after success. It is `nil` initially and immediately when the next attempt begins. Use the handler's value when callbacks may start another attempt. The property is on concrete `PassportReader`; the existing reading protocol is unchanged.
- `result.diagnosticSnapshot`: the same captured value on a successful public reader result. Optional for internal/legacy projections made without a completed scan.
- `try JSONEncoder().encode(snapshot)`: encode only this value into the app's existing diagnostic history. No decoding, raw-data import, replay, network, or storage facility was added to the reader. The app controls retention and encryption.

The handler runs synchronously on MainActor, after terminal state is detached and sensitive failure state is scrubbed, before the async call resumes. Success projection/scrubbing follows when the suspended read resumes. The snapshot itself is captured before cleanup. Keep the handler short; it can copy the Sendable value for later work. Avoid a strong reference cycle back to the reader. An overlapping read is rejected as before and is **not** a new attempt; it cannot clear or replace the active scan's diagnostics.

## Status and availability

Every check has the same four fields:

| Field | Meaning / availability |
| --- | --- |
| `attempted: Bool` | The operation began; independent from its outcome. Transport interruptions may leave a check incomplete. |
| `status` | `notAttempted`, `unavailable`, `skipped`, `unsupported`, `inProgress`, `succeeded`, or `failed`. Only `succeeded` is a pass. `inProgress` in a terminal snapshot means it began but no final result was obtained. |
| `reason` | Fixed `PassportDiagnosticReason` category. `none` on success; never interpolated text. |
| `failure` | Optional typed failure context when a failure site supplied one. A missing context does not mean success. |

`unavailable` means required input or a prerequisite was unavailable (missing SOD, trust store, data group, unparsed hashes). `skipped` means configuration prevented the check. `unsupported` means the mechanism/algorithm/version was not supported. `notAttempted` means no execution occurred or no evidence is available that it began. A verified signature does not establish trust, parse success, or matching data-group hashes.

## Field-by-field schema

Enum values encode as their declared raw strings, except `DataGroupId`, which encodes its existing integer tag (e.g. DG1 = 97). Optional properties are omitted from JSON when absent. `stage` encodes `{ "name": "readingDataGroup", "dataGroup": 97 }` or just a fixed `name`. Schema changes require an explicit version decision; consumers should reject unsupported schema versions or display them as unavailable rather than infer passes.

### Snapshot

| Field | Meaning / availability |
| --- | --- |
| `schemaVersion` | Always `1` for this schema. |
| `attemptID` | Reader-local monotonically advancing generation (UInt64, wraps past zero). Not a document ID or global ID. |
| `outcome` | `succeeded`, `failed`, `canceled`, `timedOut`. Success means the configured scan policy accepted the result; it does not imply all checks passed. |
| `terminalFailure` | Typed reason that ended a failed/canceled/timed-out attempt; nil on success. Lower-level details may be in `failures` and individual checks. |
| `verification` | Fixed set of checks described below, always present. |
| `sod` | SOD metadata and verifier evidence described below, always present even before SOD is read. |
| `dataGroups` | Exactly one entry per DG1–DG16; no COM/SOD hashes are implied. |
| `failures` | At most 32 distinct contexts. Reader observations first, then verification contexts in fixed order (manual, CMS, trust, hash, AA, CA, parsing stages). This is not an APDU transcript or strict chronology across subsystems. |
| `droppedFailureCount` | Saturating count (maximum 65,535) of contexts omitted when the bound was reached. Individual fixed verification records and terminal failure remain available regardless of this limit. |

### Verification checks

| Field | Meaning / availability |
| --- | --- |
| `sodSignature` | Result of the existing manual/CMS selection and fallback. `unavailable/missingSOD` if verification was entered without SOD; not attempted before verification begins. |
| `dataGroupHashes` | Aggregate comparison of read groups. Unavailable if SOD hash parsing failed. A signature failure does not prevent the existing independent hash comparisons. |
| `documentSignerTrust` | Signer chain validation against the provided master list, independent of SOD signature verification. |
| `countrySignerTrust` | Same chain operation as `documentSignerTrust`; these are aliases of the same evidence, not two independent validations. |
| `activeAuthentication` | AA result, including unavailable DG15, configuration skip, unsupported mechanism/algorithm, begun-but-interrupted, or completed pass/failure. |
| `chipAuthentication` | CA / existing PACE-CAM verification result, including unavailable DG14, skip, begun-but-interrupted, or pass/failure. A later BAC recovery cannot turn a CA failure into a pass. |
| `revocation` | Always not attempted in this implementation. No network or revocation verification was added. A chain error may report a revoked category without claiming a separate revocation check ran. |

The older `verificationResult` remains unchanged for acceptance and compatibility. In particular its document-signer field historically represents signature verification. The new explicit trust fields refer to chain verification. Missing or unread authentication material is unavailable in the new snapshot even where the older projection conflates it with unsupported.

### SOD

| Field | Meaning / availability |
| --- | --- |
| `stages` | Six fixed entries: `envelope`, `signedData`, `signerInfo`, `encapsulatedContent`, `ldsSecurityObject`, `dataGroupHashes`. Each entry contains `stage` and `check`. These report structural parsing, never cryptographic acceptance. |
| `version` | `v0`, `v1`, `other`; nil when not structurally readable. Arbitrary integer version values are not retained. This is the LDS Security Object version, not CMS version. |
| `ldsVersionInfo` | `present` when a sequence occupies the optional LDSVersionInfo slot; `absent` when no slot is present; `unavailable` when the structure is unreadable/unrecognized. Its string values are never retained; presence does not assert validity. |
| `contentDigestAlgorithm` | First digest AlgorithmIdentifier in SignedData's digest set, if structurally obtainable. |
| `signerDigestAlgorithm` | First SignerInfo's digest AlgorithmIdentifier, if obtainable. |
| `signatureAlgorithm` | First SignerInfo's signature AlgorithmIdentifier, if obtainable. |
| `dataGroupDigestAlgorithm` | LDS Security Object's digest AlgorithmIdentifier, if obtainable. |
| `manualVerifier` | Separate attempted/status/reason/failure for manual verification. Never overwritten by CMS fallback. |
| `cmsVerifier` | Separate attempted/status/reason/failure for CMS verification. Never overwritten by manual fallback. |
| `preferredVerifier` | `manual` or `cms` once passive verification starts; nil beforehand. |
| `fallbackAttempted` | True only when the first selected verifier failed and the second was invoked. |
| `successfulVerifier` | `manual` or `cms` only after it returns verified content; nil if neither succeeds. |

For a scan ending after SOD was read but before verification, bounded structural metadata is extracted at snapshot capture. Envelope/SignedData/SignerInfo/encapsulated-content parsing can therefore be reported, while signature verifiers and LDS hash validation remain not attempted. No additional signature verifier is run to fill a diagnostic gap. Since rc.6, valid signed v0 and v1 structures can report successful LDS parsing and hash comparison. Malformed version-dependent fields report `malformedStructure`; unknown versions report `unsupportedVersion`; validly encoded unsupported digests report `unsupportedAlgorithm`. All prevent hash comparison. Malformed DER/truncation projects to legacy `malformedSOD`. LDSVersionInfo presence is metadata, not proof that its contents passed validation; no version strings are exposed.

### Algorithm identifiers and parameters

| Field | Meaning / availability |
| --- | --- |
| `identifier` | Fixed OID enum, or `unrecognized`. Input OID text is never copied into the snapshot. Digest/signature/MGF roles have separate allowlists. |
| `parameterForm` | `absent`, `null`, `rsaPSS`, `unrecognized`, `malformed`. Opaque parameters are never retained. |
| `rsaPSS` | Present only for structurally recognized RSA-PSS parameter sequences. Describes **declared effective parameters**, not proof of what a verifier used. |
| `rsaPSS.hashAlgorithm` | Allowlisted declared hash, or default SHA-1 for an omitted field. |
| `rsaPSS.maskGenerationAlgorithm` | MGF1/default MGF1 or `unrecognized`. |
| `rsaPSS.maskGenerationHashAlgorithm` | Nested allowlisted digest for MGF1; default SHA-1 for omitted MGF field; nil when unavailable. |
| `rsaPSS.saltLength` | Declared integer in 0…512; default 20 when omitted; nil if outside the bound. |
| `rsaPSS.trailerField` | `1` only; default 1 when omitted; nil for another declared value. |

Digest allowlist: SHA-1/224/256/384/512. Signature allowlist: RSA encryption, RSA with SHA-1/224/256/384/512, RSA-PSS, ECDSA with SHA-1/224/256/384/512. Mask allowlist: MGF1. Exact OIDs are defined by `PassportDiagnosticAlgorithm`. A known identifier does not imply verifier support (e.g. manual verification currently rejects generic `rsaEncryption`, while CMS can accept it). Malformed/duplicate PSS parameter structure yields `malformed`, without raw parameters.

### Data-group entries

| Field | Meaning / availability |
| --- | --- |
| `dataGroup` | Fixed DG1–DG16 identifier. |
| `wasRead` | A parsed group was retained in the working model at capture. |
| `coverage` | `covered` for a validated hash entry, `notCovered` only after the full hash list parsed successfully without that group, otherwise `unavailable`. Partial valid entries survive a later malformed entry. |
| `comparison` | Pass/fail only if an actual comparison occurred. Covered-but-unread is unavailable/missingDataGroup. Read-but-uncovered is unavailable/hashNotCovered. Unparsed hashes are unavailable/prerequisiteFailed. No hashes or lengths of individual document fields are retained. |

### Failure context and parser metadata

| Field | Meaning / availability |
| --- | --- |
| `subsystem` | Fixed reader, coreNFC, transport, parser, cryptography, trust, authentication, policy category. |
| `operation` | Fixed scan, connect, invalidateSession, sendCommand, parseDataGroup, parseSOD, manualVerification, cmsVerification, compareHashes, validateChain, activeAuthentication, chipAuthentication category. |
| `stage` | Existing typed scan stage, with a fixed group ID only for readingDataGroup. |
| `reason` | Fixed category: malformedStructure, unsupportedVersion/Algorithm, signedContentDigestMismatch, signatureInvalid, hashMismatch, trust categories, interruptions, resource/input/policy errors, or unknownFailure. Never parsed from arbitrary descriptions. |
| `coreNFCCode` | Native `NFCReaderError.code.rawValue` observed before translation; nil for non-CoreNFC errors. NSError domains/userInfo and unknown error codes are not retained. |
| `statusWord` | Failing response SW1/SW2 packed into UInt16. No command bytes, successful-response sequence, APDU body or transcript. Captured even when translated into access rejection or missing-required-group errors. |
| `parser` | Optional bounded structure metadata at instrumented parser sites. |
| `certificateValidationCode` | X509 verification return code at the chain failure site; nil for setup/extraction errors. No error queue strings, certificate names, serials, dates or bytes. |
| `parser.expectedTag`, `actualTag` | Only known ASN.1/data-group tag values; unrecognized tags omitted. Allowlist: 02, 04, 05, 06, 13, 30, 31, 60, 61, 63, 65–70, 75–77, A0–A3 (hex). |
| `parser.expectedLength`, `actualLength`, `offset` | Only structural byte counts/offsets in 0…16,777,216; omitted outside bounds or when unavailable. ASN.1 offsets are relative to the parser input (CMS body or LDS content), not the entire chip stream. No arbitrary numeric field values. |

Chain categories include trustStoreUnavailable, certificateUnavailable, issuerNotFound, certificateExpired, certificateNotYetValid, certificateSignatureInvalid, certificateRevoked, invalidCertificatePurpose, chainInvalid and resourceFailure. Native CMS verification exposes signatureInvalid for a broad verify failure; no unsupported-algorithm inference is made from OpenSSL error strings.

## Limits and separately identified defects

- The rc.5 v1 parser defect is fixed in rc.6 with complete version-dependent validation and independently signed acceptance/rejection tests. Physical-document validation remains outstanding.
- The manual RSA-PSS implementation currently selects SHA-256 and automatic salt length rather than applying all declared PSS parameters. The snapshot deliberately labels its PSS metadata as declared. Full parameter enforcement is separate verification work; this task does not change it.
- Existing manual/CMS implementations select/expose the first signer; diagnostics do not claim exhaustive multi-signer or digest-set analysis. No extra verification run is forced after success.
- Some legacy crypto and authentication helpers expose only booleans or fixed errors, so detailed native causes remain unavailable. Numeric OpenSSL error queues are not collected. Parser offsets are supplied at SimpleASN1 boundaries and instrumented LDS failures; other legacy parser failures may have tags only or no offsets.
- Legacy `PassportReaderFailure.verificationReason` remains the first policy-relevant reason. Use the snapshot to preserve all results. Do not use a successful parse stage or scan outcome as a trust decision.
- Snapshot generation retains no raw data. Swift/framework memory scrubbing remains best-effort data minimization, not guaranteed zeroization. No physical-device NFC callback/RF behavior is established by simulator tests.

## Candidate pin and repinning

The diagnostic API was introduced in `notary-2.3.1-privacy.6-rc.5`. The new annotated `notary-2.3.1-privacy.6-rc.6` candidate for the SOD v1 correction is prepared locally at `e0fad5d`, on maintained local `main`; publication is blocked by GitHub HTTP 403. Its peeled commit is the exact SHA pin after an authorized writer publishes it. Remote main remains rc.5; all earlier tags/upstream snapshots remain unchanged. Schema 1 and all public call signatures remain compatible.

Repin the consuming app in a separate task. Exercise real v0/v1 success, malformed/tampered rejection, RF loss, timeout/cancellation and back-to-back scans with its custom logger and encrypted history before promoting a production tag. Ship RSA-PSS parameter enforcement separately with its own review and new tag.
