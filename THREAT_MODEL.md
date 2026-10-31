# NFCPassportReader Fork Threat Model

This fork reads identity-document NFC data. Privacy, security, correctness, and maintainability are release-blocking concerns.

## Lifecycle audit additions (privacy.6 candidate 2)

Overlapping calls cannot alter an active scan's credential/policy. Main-actor transport state is revoked before terminal callbacks, preventing late NFC responses from continuing a canceled authentication or contaminating a subsequent scan. Native transport errors are mapped to fixed categories; the legacy internal formatter is redacted. Typed terminal diagnostics contain only reason and stage. No new network, persistence, raw-logging or export path is introduced.

Optional authentication does not suppress connection loss, timeout, response-integrity failures or failed BAC recovery. Required PACE and verification policies fail closed. Missing required files and mismatched file types cannot produce a successful identity read. Reconnection is restricted to access establishment before document data is collected; a failed open CA chain requires a wholly new scan. Handler teardown cannot erase another owner's live secure messaging or DG14 metadata.

Crypto hardening covers AES-CMAC native parameter lifetimes, complete PACE domain-parameter copying, public-key validation, reflected PACE key rejection and fixed-length MAC comparison. B1 addressing and DO85 protection prevent offset wraparound and incorrect protected reads of large data groups. CA v1 keys use a complete GA command, with extended length when necessary, and an authenticated response under the new session keys is required before reporting success. Existing version gates still reject unsupported CA protocol versions.

An already-submitted radio command cannot be recalled, and synchronous native crypto cannot be preempted. Revoked responses are discarded; deadlines are checked at scan boundaries. Managed-memory cleanup is best effort. Synthetic tests, including complete DH/ECDH GM PACE exchanges, do not replace physical issuer/device testing or a complete independent protocol-conformance audit. Keep the release as a candidate until that matrix is recorded.

## Sensitive Assets

- MRZ values and MRZ-derived access keys.
- Passport number, dates of birth, expiration dates, checksums, names, nationality, gender, addresses, and personal numbers.
- APDU request/response data and low-level NFC status details.
- BAC, PACE, secure-messaging, active-authentication, and chip-authentication keys, nonces, MACs, challenges, signatures, and intermediate values.
- Decrypted data groups, SOD data, certificates with sensitive metadata, and passport image/signature bytes.
- Any raw output from deprecated dump/import/export APIs.

## Attacker And Failure Assumptions

- The passport chip and NFC link are untrusted input sources and may return malformed, truncated, inconsistent, or unsupported data.
- Developers may accidentally log, persist, upload, copy, or display sensitive values while debugging app integration.
- Host apps may confuse "chip read succeeded" with "passport authenticity was verified".
- NFC sessions can be canceled, backgrounded, timed out, interrupted, or completed concurrently.
- Real passport interoperability can differ by country, chip generation, BAC/PACE support, data-group size, and optional authentication features.

## Primary Protections

- Logging is off by default and opt-in logging uses typed redacted events only.
- Public error descriptions and NFC sheet messages are privacy-safe by default.
- Sensitive low-level parsing and crypto errors should fail closed without exposing raw values.
- Scan profiles and photo policy let apps request only the data groups they need.
- `PassportReaderSecurityPolicy` centralizes photo access and verification strictness.
- `PassportReaderPACEPolicy` lets callers keep current BAC fallback behavior, require PACE when advertised, or require an explicit CAN/PIN/PUK credential for workflows that should fail closed.
- `PassportIdentityResult` gives host apps normalized fields and verification metadata without MRZ text, raw data groups, APDUs, certificates, keys, or image bytes.
- `PassportChipReadResult` and `PassportReader.readPassportIdentity(...)` provide the app-facing scan path and do not return the internal raw model to the host app.
- Raw passport dump import/export APIs are not public surfaces in this fork.
- `PassportReaderFailure` carries stage-aware retry metadata without exposing low-level error payloads, and data-group read reports describe requested/advertised/read/skipped/blocked/unsupported/failed states without raw contents.
- `PassportInteroperabilityRecord` is limited to non-identifying real-device compatibility notes and rejects MRZ-like strings or long hex samples.
- Parser and crypto boundaries should reject malformed input without traps, out-of-bounds reads, or empty cryptographic outputs.
- Secure Messaging protected responses must fail closed when required DO'85/DO'87, DO'99, or DO'8E are missing, truncated, malformed, or inconsistent.
- DG2, DG7, and DG12 image parsing applies explicit size, structure, and image-header bounds before retaining image bytes or allowing image decode.
- DG11 and DG12 optional text parsing applies per-field size bounds before retaining decoded strings.

## Verification Trust Assumptions

- A successful NFC read alone is not proof of document authenticity.
- Passive authentication requires SOD signature and data-group hash checks.
- Signer trust depends on the configured master list and certificate validation path.
- Active authentication and chip authentication are meaningful only when supported, attempted, and passed.
- Apps should use `PassportVerificationResult`, `PassportTrustLevel`, and `PassportReaderSecurityPolicy` instead of inferring trust from individual booleans.
- Verification-detail fields distinguish safe causes such as missing master list, missing SOD, skipped authentication, unsupported authentication, hash mismatch, signer untrusted, and attempted failure without exposing raw hashes, certificates, APDUs, or cryptographic material.
- Revocation checking is not currently performed by this fork and must not be implied in user or support copy.

## App Integration Risks

- Do not persist scanned identity data unless the app has a deliberate, user-approved retention policy.
- Do not include scanned values in logs, analytics, crash reports, screenshots, clipboard contents, bug reports, or support diagnostics.
- Obscure identity data when the host app backgrounds or appears in the app switcher.
- Prefer in-memory review flows and redacted UI modes for sensitive fields.
- Use `PassportChipReading` and `PassportReaderFixture` for simulator/UI tests instead of real passport fixtures.

## Release Checks

- Build the iOS package target.
- Build the iOS test bundle.
- Run the iOS Simulator test suite through `scripts/release_check.sh`.
- Run `scripts/privacy_scan.sh`.
- Run `git diff --check`.
- Run targeted searches for raw diagnostics, risky sinks, runtime traps, and removed raw import/export APIs.
- Manually scan real passports on device before tagging, without recording real passport values.

## PACE fallback recovery boundary

Failed PACE can leave a chip inside a GENERAL AUTHENTICATE chain or with secure messaging the terminal cannot use. The fallback path clears local PACE/CAM/CardSecurity and secure-messaging state, drops obsolete transport references, restarts polling when initialization reached the chip, and selects the passport application on a newly activated tag before BAC. A failed selection permits one additional reactivation; retry counts are scan-local. Session timeout/cancellation and scan IDs prevent stale recovery from continuing a canceled scan. Re-polling may detect another physical tag: cached security information is discarded and BAC authenticates it with the supplied MRZ credential; this flow makes no UID-based identity assertion.

No fabricated final GA/public key is transmitted as an abort command. The transport's GENERAL AUTHENTICATE wrapper would encode the old commented `83 01 00` suggestion inside a `7C` dynamic authentication object with the final-chain class and unwrap the response as authentication data. ICAO 9303-11 §4.4.4–4.4.5 and BSI TR-03110-3 Appendix B.1 define that object as an ephemeral public key, not a portable abort operation. BSI Appendix B.13 defines chain handling, not that workaround. A protocol/transport restart is used instead; hardware interoperability remains a release validation requirement.

Fallback errors contain only a fixed typed reason and stage. Raw chip errors, credential values, APDUs, and cryptographic material are not attached to preparation failures. Swift cleanup minimizes lifetime but does not guarantee zeroization of every copied/framework buffer. PACE-required policies prohibit BAC even in later reauthentication paths.

## Standards fixtures and test-only trust roots

The independent protocol and signed-document corpus is described in [Tests/README.md](Tests/README.md). Its published vectors, fictitious signed documents and synthetic root certificates are test-bundle resources only. Deterministic entropy import is linked only to tests; production retains its CSPRNG paths. The offline generator never writes private signing keys. Test roots must never enter an app master list. Assertions do not dump buffers.

PACE authority references are bounded, structurally checked and discarded without logging or exposure. Accepting these optional objects does not enable Terminal Authentication or confer certificate trust. CAN/PIN/PUK encoding now follows the specified character-string KDF input; invalid encoding produces a constant redacted failure. This improves interoperability without changing PACE-required or BAC-fallback policy. Physical NFC reset/session behavior still requires device validation.

## Diagnostic snapshot boundary (notary-2.3.1-privacy.6-rc.5)

The explicitly requested diagnostic API retains bounded immutable enum/numeric evidence after model scrubbing: structural counts/offsets, failing APDU status words, native Core NFC codes, X509 verification codes, and role-allowlisted algorithm/PSS metadata. It does not retain command/response contents, hashes, keys, certificates, identity fields, photos or arbitrary strings. Unknown OIDs/tags and out-of-bound parameter values are omitted or categorized. Error descriptions and NSError userInfo are never diagnostic inputs. These details are delivered through an explicit handler/value API; existing high-level console logging remains opt-in and unchanged.

Publication and collection are MainActor-isolated and scan-generation guarded. Terminal results are frozen before external invalidation/display/log/progress callbacks; subsequent cancellation cannot replace them. Each new accepted attempt clears previous state, and bounded buffers prevent unbounded diagnostic history in the reader. Host-controlled encoded history must store the snapshot separately from identity results. Field availability and known verification limitations are documented in `DIAGNOSTICS.md`. No replay facility, additional trust bypass or automatic diagnostic persistence is introduced.


## Standards compatibility changes (rc.7)

Both SOD verifiers preflight typed algorithm declarations, enforce PSS hash/MGF/salt/trailer and restricted-key parameters, and bind certificates through CMS SignerIdentifier. Every signer must verify; trusted policy validates every corresponding chain. Unrelated first certificates cannot supply trust to another signer. The displayed diagnostic algorithm/issuer metadata remains representative of the first signer; aggregate verification covers all. SOD v0/v1 structure and read-group hash checks remain independent of signature/trust outcomes and survive failure scrubbing.

Explicit PACE parameters from unauthenticated CardAccess are accepted only when equal to known standard groups; no attacker-defined group is used with a password. CA checks algorithm/key family agreement, preserves explicit zero identifiers, permits same-key cipher alternatives and requires authenticated confirmation after replacing messaging keys. AA rejects malformed RSA recovery and requires explicit, permitted ECDSA hash metadata and prime/uncompressed EC keys. ISO39794 decoding is bounded and skips declared extension fields without scanning opaque bytes for an image.

Offline revocation is opt-in: a local bundle is checked against each actual signer's direct issuer (including a CSCA link path), CRL AKI/signature/current interval/number and serial status. Configured invalid or unavailable lists fail trusted verification. New `requiresRevocationCheck` additionally requires trusted passive authentication. All preset defaults remain unchanged. There is no network lookup, online tracking, CRL-URL following, raw logging or public certificate/challenge/image dump. Trust-anchor provenance, refresh and persistent anti-rollback state are app responsibilities; a current signed CRL alone cannot prove the app has obtained the newest publication.

Terminal Authentication/LDS2 remain a separate project by explicit user decision. None of these changes grants restricted-biometric access or writes to a document. The coverage inventory distinguishes synthetic/Simulator evidence from outstanding physical issuer/device/RF validation.

## Repeated edge-case audit (privacy.6-rc.8)

Unsigned COM cannot suppress signed SOD authentication-group coverage when evaluating when-supported policies. Unknown availability or missing advertised authentication data fails those policies; a genuine signed absence remains permissible. Actual CardSecurity CAM results survive the absence of DG14. CAM keys are bound to their declared identifier, and explicit CA suites prevent inference for unrelated keys. Signature, trust and read-group integrity remain distinct checks.

Every issuer-matching supplied CRL must authenticate and meet the supported complete/direct profile. Conflicting highest-number bodies, invalid replacement signatures and unsupported entry semantics are rejected, independent of bundle order. This does not prevent replay of a still-current older bundle across scans/launches; the trust-store owner must handle refresh and rollback.

ASN.1 nodes share bounded immutable input instead of multiplying retained payloads by nesting depth. Internal nodes may retain their complete source buffer until released; this is not secure erasure. No node/raw bytes are exposed through diagnostics, and existing cleanup removes the owning model/handler data. Native boundaries reject trailing CMS and malformed identifiers. Compressed image/declared-dimension limits do not establish a decoded-pixel memory budget; codec stress and host rendering need a separate device-measured resource review.
