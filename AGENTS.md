# AI Working Instructions

This fork handles identity-document NFC data. Treat privacy, security, correctness, and maintainability as release-blocking concerns.

## Project Source Of Truth

- Use `NFCPASSPORTREADER_FORK_SECURITY_AND_FUNCTIONALITY_PLAN.md` as the source of truth for this fork's goals, priorities, app context, migration options, and verification checklist.
- Read the planning document before starting substantive security, API, logging, verification, or app-integration work.
- Keep the planning document current as work progresses. When a task completes, update it with decisions made, implementation status, changed priorities, migration notes, verification results, and any remaining follow-up work.
- If implementation reality conflicts with the planning document, resolve the conflict explicitly by updating the document or documenting why the plan needs to change.

## Core Priorities

- Preserve user privacy by default. Never log or expose MRZ values, passport numbers, dates of birth, expiration dates, checksums, APDUs, BAC/PACE keys, session keys, random challenges, MAC inputs or outputs, decrypted data groups, certificates with sensitive metadata, or passport image bytes.
- Prefer secure, typed, redacted APIs over stringly-typed diagnostics or raw byte access.
- Keep behavior compatible with the app's current `NFCPassportReader` usage unless an API change is deliberate, documented, and migration guidance is included.
- Do not skip known issues just to finish a task. If a task uncovers related safety, correctness, compiler, or test problems, either fix them or document them clearly as follow-up work with rationale.
- Favor future-proof changes that are small, explicit, and easy to audit.

## Completion Standard

A task is not complete until all applicable items are true:

- The code builds for the intended iOS package target.
- New or changed behavior has focused tests, or the reason tests are not practical is documented.
- There are zero compiler warnings from code changed in this fork.
- Public API changes are documented in `readme.md`, inline doc comments, or a migration note, as appropriate.
- Security/privacy impact has been reviewed, especially logging, error messages, retained data, and diagnostics.
- Sensitive values are not printed, persisted, surfaced in errors, or accidentally included in test fixtures.
- Any remaining limitations, risks, or follow-up tasks are documented before handing off.

## Logging And Diagnostics

- Logging must be off or privacy-safe by default.
- Safe logs may describe high-level state only, such as session start, tag detected, PACE fallback, BAC succeeded, reading a named data group, verification succeeded or failed, cancellation, timeout, or connection loss.
- Do not add raw string logging APIs that make sensitive output easy to reintroduce.
- Prefer typed events with redacted payloads.
- Avoid including low-level status words, raw tag descriptions, or cryptographic details in public errors unless there is an explicit privacy-reviewed diagnostic mode.

## Testing Expectations

- Add tests for redaction, logging policy, error mapping, and API behavior when those areas change.
- Include negative tests for sensitive patterns such as MRZ-like strings, access-key material, long hex dumps, APDU-like bytes, `Kseed`, `KSenc`, `KSmac`, `RND.IFD`, `RND.ICC`, and JPEG-like byte chunks.
- Keep fixtures synthetic. Do not use real passport data.
- Use the existing test style unless a better structure is clearly warranted.

## Documentation Expectations

- Document every public API addition, removal, rename, default-value change, or behavior change.
- Include migration notes when app-side call sites need to change.
- Keep docs practical: what changed, why it changed, how to use it, and any privacy or compatibility implications.
- Update examples only when they remain safe and do not encourage sensitive logging.

## Build And Verification

- This package is iOS-focused. In this environment, verify iOS builds with:

  ```sh
  DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild -scheme NFCPassportReader -destination generic/platform=iOS build
  ```

- `swift test` may fail at baseline because SwiftPM evaluates the package against macOS while the OpenSSL dependency requires a newer macOS target. Do not treat that as proof the iOS package is broken; use an iOS/Xcode verification path unless the package manifest is deliberately changed to support macOS tests.
- Before final handoff, run a targeted search for risky logging or diagnostics in changed files and any touched logging-adjacent files.

## Git And Release Hygiene

- Keep changes scoped and reviewable.
- Use the app-pinned `2.3.0` baseline as the compatibility reference unless the task explicitly upgrades upstream.
- Do not rewrite upstream history.
- Use clear commit messages that call out privacy, API, test, or documentation implications.
- Tags for app consumption should use an explicit fork suffix, such as `2.3.0-notary.1`.
