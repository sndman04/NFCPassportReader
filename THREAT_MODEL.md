# NFCPassportReader Fork Threat Model

This fork reads identity-document NFC data. Privacy, security, correctness, and maintainability are release-blocking concerns.

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
- Secure Messaging protected responses must fail closed when DO'87, DO'99, or DO'8E are missing, truncated, malformed, or inconsistent.
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
