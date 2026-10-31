# Pinned public stress corpora

These tests exercise the fork's production cryptographic, trust/CRL and DG2 image entry points using public synthetic/adversarial data. They are not passport captures, ICAO certification, a WebPKI conformance claim or physical NFC validation. The full original signed v0/v1 SOD tests remain unchanged and run with both verifier preferences and existing policies.

## Reproduce

Use Python 3 with `cryptography` installed. The download script executes no upstream code, verifies every source's pinned size/SHA-256, and retains only the fields needed by the adapters. Run from the source repository:

```sh
python3 scripts/fetch_external_corpora.py
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/ExternalCorpusTests
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -enableAddressSanitizer YES -test-iterations 3 -only-testing:NFCPassportReaderTests/ExternalCorpusTests
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
```

The raw cache is ignored under `tmp/external-corpora/`; normalized XCTest resources are ignored under `Tests/NFCPassportReaderTests/Fixtures/ExternalCorpora/`. Without fetching, six optional methods explicitly skip. Three permanent methods still run using the tracked `external-regressions.json`: nine public-key cases, 22 certificate/CRL cases, and two derived negative controls. Recreate that fixed subset deliberately with `python3 scripts/fetch_external_corpora.py --refresh-regressions`; it saves no private keys. The optional ECDH suite uses Wycheproof's published non-secret scalar examples. No corpus is included in the shipping library target.

## Sources and coverage

`manifest.json` records immutable source revisions and individual file hashes. `profile-mapping.json` records every different acceptance expectation, preserving upstream verdicts and the standards rationale. It is not generated from test outcomes by the fetch script.

| Source | Pinned revision | Executed cases and boundary |
| --- | --- | --- |
| [C2SP Wycheproof](https://github.com/C2SP/wycheproof) | `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` | 26 files: 6,817 RSA PKCS#1/PSS, DSA and ECDSA signature vectors; 2,575 P-256/P-384/P-521 ECDH vectors; 311 AES-CMAC vectors. |
| [C2SP x509-limbo](https://github.com/C2SP/x509-limbo) | `1080e565f26e544bbe9cf99953be8a57c08e7e20` | 119 certificate/CRL probes: 103 match original expectations; 16 documented profile differentials run separately. 9,683 other cases excluded with reasons in `tmp/external-corpora/excluded-limbo.json`. |
| [OpenJPEG data](https://github.com/uclouvain/openjpeg-data) | `39524bd3a601d90ed8e0177559400d23945f96a9` | Ten malformed/header-only JPEG 2000 files, each <1 KiB, passed unchanged through synthetic 39794-5 DG2 wrappers and the actual ImageIO path. No photograph corpus was imported. |

That is **9,832 external inputs**, plus the permanent repeated subset/derived controls. Signature testing uses the real typed SOD signature primitive over the unchanged external messages/signatures; it does not pretend these are full CMS SODs. Six signature vectors are upstream `acceptable`, permitting either result. ECDH has 688 `acceptable` vectors; an accepted one must produce the exact published shared secret. CMAC covers 63 valid and 248 invalid/truncated-tag cases. No timing/side-channel resistance is established by functional vector tests.

Three ECDH cases (`359`, `799`, `660` in the respective curve files) omit the optional cofactor and are marked invalid upstream. [SEC 1 v2.0 C.2](https://www.secg.org/sec1-v2.pdf) permits omission. This reader accepts omission only when all remaining explicit parameters match a known ICAO group, and the tests require the correct published secret. Contradictory cofactors (`361`, `801`, `662`) are rejected before native normalization can erase the declaration. This complements the existing PACE parameter validation, rather than relaxing it. See ICAO Part 11 §9.5.2/Table 12.

The Limbo adapter supplies intermediates as **untrusted** and uses the fixture's explicit verification time. Fractional fixture times are parsed before conversion to X.509 whole-second resolution. Its CRL checker uses the production current-time path; selected CRL dates span the test run. A future run must review any genuinely expired fixture rather than weakening time checks. Original private signing keys are omitted from the normalized subset, and the online/production-certificate category is excluded.

The 16 Limbo differentials are: nine name-constraint cases, one name-constraint CVE case, one policy-constraint case, one empty-EKU case, two serial issuance-lint cases, one missing-CRL-key-usage case, and one explicitly trusted cross-signed anchor missing AKI. Exact IDs and expectations are in the machine-readable mapping. Name/policy/extended-purpose behavior belongs to general PKI features outside the ordinary ICAO DS/CSCA profile; see [ICAO Part 12 §7.1.1 and Appendix D.2](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p12_cons_en.pdf). The reader is not a complete certificate issuance-profile linter. [RFC 5280 §4.1.2.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.2) distinguishes issuer serial requirements from graceful handling by consumers. ICAO requires explicit CA CRL-signing usage; a configured trust anchor's own issuer AKI is not how trust is established in its key (Appendix D.1.1.1). These measured differences are **not** reported as generic X.509 conformance passes. Broad issuance lint, DNS name validation and arbitrary constraint/path-graph completeness remain separate work, not inferred support.

Ten image inputs parsed as DG2; ImageIO returned two UIImage objects and rejected eight. Small thumbnail draws were attempted only after checking the returned dimensions, and DG2 image storage was scrubbed afterward. ImageIO emitted fixed codec error messages for malformed inputs. This is bounded crash/resource regression evidence, not proof of a decoder memory ceiling or of semantic validity for the two returned images. The distributed OpenSSL and system ImageIO binaries are not rebuilt with sanitizer instrumentation.

## Attribution and redistribution

Wycheproof and x509-limbo are Apache-2.0; license texts are included here. The tracked 68 KiB subset retains only public keys, synthetic certificates/CRLs and upstream verdicts, with original bytes unchanged and fields/selection adapted for this test harness. The larger corpora remain fetched/ignored. OpenJPEG data has heterogeneous provenance; the selected bytes are not redistributed in this repository. This work does not import OpenPACE code, NIST PKITS or OpenSSL CMS corpora, and makes no test claim for those datasets.

Final rc.9 validation: 484 XCTest methods and the full iOS/API/privacy/NFC-boundary release workflow passed. Three AddressSanitizer iterations of nine external-corpus methods produced 27 successful executions, zero skips/failures. The app tag is `notary-2.3.1-privacy.6-rc.9` / `4b21e2762533f87e9d8c8292d611ecaab8cd7df5`. This remains simulator/synthetic evidence.
