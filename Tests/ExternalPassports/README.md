# External synthetic passport specimens

These are independent document-shaped inputs, used without repairing or re-signing their bytes. They are not an issuer compatibility catalog. Their published descriptions are not acceptance oracles: a mathematically valid signature can cover malformed files.

## Sources and outcomes

| Input | Source/revision | Verified outcome |
| --- | --- | --- |
| Bundled signed specimen | [pod-passport-scanner](https://github.com/jeswr/pod-passport-scanner/tree/d9c540b61f2ddad9ded26c48acfc600f68b5cadb/Sources/Resources/SamplePassport), `d9c540b61f2ddad9ded26c48acfc600f68b5cadb` | Original SOD v0 passes both real signature verifiers; all four original DG hashes match. DG2 declares a zero-length face record despite containing 174 record bytes. DG14 uses an OCTET STRING instead of the required SET. Both are rejected by typed file reads. DG1/DG11 and the SOD envelope parse. No trust root is supplied. |
| Utopia TD3 | [Proxmark3 generator](https://github.com/RfidResearchGroup/proxmark3/blob/754bbae3d946429a6354cd34a97a2dd29ce6f157/tools/ePassport/tools_make_sample.py), `754bbae3d946429a6354cd34a97a2dd29ce6f157` | Generic CMS signature and seven raw DG hashes verify. SOD has content type `1.2.840.10008.5.1.4.1.1.1` instead of ICAO `2.23.136.1.1.1`; both SOD verifiers reject it. DG2 has zero-filled face metadata; DG7 uses a biometric container instead of its displayed-signature structure; DG14 has malformed known authentication entries. Those three files reject. COM/DG1/DG11/DG12/DG15 and the SOD envelope parse. |
| Utopia TD3 tampered | Same unchanged generator | Same authenticated SOD as TD3, with DG2 changed after signing. Generic signature remains valid; isolated hash comparison detects exactly DG2. Complete SOD verification already rejects the content type before hash comparison. The adapter does not bypass that rejection in a reader flow. |
| Utopia TD1 ID card | Same unchanged generator | COM/DG1 parse; malformed DG2 rejects; no SOD is supplied. Passive-integrity and trusted policies cannot pass. This is an ID-card-shaped negative control, not a valid signed passport. |

The source itself describes fictional identity data and non-person drawings. The retained MIT specimen uses a tiny synthetic image. No real passport capture is used. The two sources do **not** add a complete conforming external positive passport; the existing independently signed v0/v1 acceptance controls continue to supply that evidence.

Standards basis: [ICAO Doc 9303 Part 10](https://www.icao.int/sites/default/files/publications/DocSeries/9303_p10_cons_en.pdf) §§4.6.2.1–4.6.2.3/§7 for SOD/CMS and the content OID; §4.5.6/§4.7.2 for the ISO biometric record; §4.7.7 Table 62 for DG7; §4.7.14.2 for the DG14 SET. Part 11 §§9.2.4/9.2.7 specify the known AA/key-information entries. We do not change a malformed specimen's expected outcome merely because another implementation tolerates it.

## Reproduce

From the source repository, use Python 3.10+ with Pillow and cryptography:

```sh
python3 scripts/prepare_external_passports.py
# Also fetch the earlier crypto/trust/image corpora for a full zero-skip run:
python3 scripts/fetch_external_corpora.py
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -only-testing:NFCPassportReaderTests/ExternalPassportTests
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer xcodebuild test -scheme NFCPassportReader -destination 'platform=iOS Simulator,name=iPhone 17,OS=26.5' -enableAddressSanitizer YES -test-iterations 3 -only-testing:NFCPassportReaderTests/ExternalPassportTests
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer scripts/release_check.sh
```

`manifest.json` pins every source file's revision, size and SHA-256, including the pure-Python asn1crypto 1.5.1 wheel. This preparation command deliberately runs the four reviewed Proxmark3 generator/helper files in a fresh temporary directory. Upstream package initializers, GUI, NFC clients and unrelated code are not imported. The generator performs only synthetic generation and local writes/copies; its directory replacement is confined to its own fresh output. It prints no document content through this adapter. Private signing keys exist only in memory. The subprocess output is captured and discarded; preparation reports only counts, versions and outcomes.

Generated Proxmark3 data and downloaded GPL source remain ignored under `tmp/passport-samples/cache` and `Tests/NFCPassportReaderTests/Fixtures/ExternalPassports`. No Proxmark3 implementation or generated drawing/identity corpus is redistributed in the fork. The source licenses remain in the verified download cache. Re-running generation changes random public keys/signatures but preserves every scenario; no original fixture is silently re-signed or fixed.

The small MIT input is retained byte-for-byte as `Fixtures/external-passport-specimen.json`, with [its license](SPECIMEN-LICENSE.txt). Four XCTest methods run offline from that committed file. Three Proxmark3 methods explicitly skip when generation has not run. All fixture resources belong to the test target, not the shipping library.

The tests exercise 26 individual file reads through the real TagReader/reader/parser path with an in-memory transport: 17 parse and nine structurally reject. Every one of the 1,179 truncated prefixes of the five retained specimen files rejects. Both verifier preferences, corrupted signatures, a changed signed DG11, missing trust, policy failures, and immutable snapshots after scrubbing are covered. Hash-only component tests deliberately hash opaque original file bytes; this is not a complete passport acceptance path. `.notaryStrict` retains its documented passive-integrity meaning, not issuer trust or complete signed-group coverage.

This run provides no physical NFC, BAC/PACE/CA/AA exchange, production trust-root or issuer-device interoperability evidence. The public samples lack the material needed for those claims. No network contact with sample-app upload endpoints occurs.

Results: all seven focused methods passed; the complete workflow passed 491 tests with zero failures/skips. Three AddressSanitizer iterations passed 21 executions with no finding. Production is unchanged from annotated `notary-2.3.1-privacy.6-rc.9` (`4b21e2762533f87e9d8c8292d611ecaab8cd7df5`); the app does not need a new pin for these test-only additions.
