#!/usr/bin/env python3
"""Independent signed LDS v0/v1 structure corpus; never saves private keys.

Preserves the original diagnostic-passports.json v0/v1 regression bytes and root.
Only writes sod-version-passports.json and its test-only sod-version-csca.pem.
Requires Python cryptography; tests consume committed output offline.
"""
import hashlib
import json
from generate_synthetic_passport_fixtures import OUT, tlv, seq, integer, oid, alg, setof, certificate
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def main():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = certificate(root_key, 'SYNTHETIC SOD VERSION CSCA', ca=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = certificate(key, 'SYNTHETIC SOD VERSION SIGNER', root, root_key)
    base = json.loads((OUT / 'diagnostic-passports.json').read_text())['v1']
    groups = [(1, bytes.fromhex(base['dg1'])), (11, bytes.fromhex(base['dg11']))]
    sha256_oid = '2.16.840.1.101.3.4.2.1'
    info = seq(tlv('13', b'0108') + tlv('13', b'060000'))

    def entry(number, data, digest='sha256'):
        return seq(integer(number) + tlv('04', hashlib.new(digest, data).digest()))

    entries = b''.join(entry(i, data) for i, data in groups)

    def content(version=1, version_info=info, algorithm=None, hashes_der=None, extra=b''):
        return seq(integer(version) + (alg(sha256_oid) if algorithm is None else algorithm)
                   + seq(entries if hashes_der is None else hashes_der) + version_info + extra)

    contents = {}
    digests = {'sha1': '1.3.14.3.2.26', 'sha224': '2.16.840.1.101.3.4.2.4',
               'sha256': sha256_oid, 'sha384': '2.16.840.1.101.3.4.2.2', 'sha512': '2.16.840.1.101.3.4.2.3'}
    for version in [0, 1]:
        for digest, digest_oid in digests.items():
            for parameters in ['absent', 'null']:
                contents[f'v{version}_{digest}_{parameters}'] = content(
                    version, b'' if version == 0 else info,
                    seq(oid(digest_oid) + (b'\x05\0' if parameters == 'null' else b'')),
                    b''.join(entry(i, data, digest) for i, data in groups))
    contents['v1_other_version_strings'] = content(version_info=seq(tlv('13', b'0299') + tlv('13', b'159999')))
    contents['v1_sixteen_hashes'] = content(hashes_der=b''.join(
        entry(i, dict(groups).get(i, bytes([i]))) for i in range(1, 17)))
    contents.update({
        'v0_with_info': content(0),
        'v0_extra_field': content(0, b'', extra=b'\x05\0'),
        'v1_missing_info': content(version_info=b''),
        'v1_extra_field': content(extra=b'\x05\0'),
        'v1_duplicate_info': content(extra=info),
        'v1_reordered_fields': seq(integer(1) + alg(sha256_oid) + info + seq(entries)),
        'v1_missing_hashes': seq(integer(1) + alg(sha256_oid) + info),
        'unsupported_v2': content(2),
        'unsupported_v3': content(3),  # CMS remains v3 in every fixture; this inner v3 is invalid.
        'unsupported_large_version': content(1 << 80),
        'v1_empty_hashes': content(hashes_der=b''),
        'v1_one_hash': content(hashes_der=entry(*groups[0])),
        'v1_seventeen_hashes': content(hashes_der=b''.join(entry(i, bytes([i])) for i in range(1, 18))),
        'v1_duplicate_hash': content(hashes_der=entry(*groups[0]) * 2),
        'v1_zero_group': content(hashes_der=entry(0, b'') + entry(*groups[1])),
        'v1_unknown_group': content(hashes_der=entry(17, b'') + entry(*groups[1])),
        'v1_bad_hash_length': content(hashes_der=seq(integer(1) + tlv('04', bytes(31))) + entry(*groups[1])),
        'v1_extra_hash_field': content(hashes_der=seq(integer(1) + tlv('04', bytes(32)) + b'\x05\0') + entry(*groups[1])),
        'v1_unknown_digest': content(algorithm=alg('1.2.3.4.5.6')),
        'v1_digest_bad_parameters': content(algorithm=seq(oid(sha256_oid) + integer(0))),
        'v1_digest_nonempty_null': content(algorithm=seq(oid(sha256_oid) + tlv('05', b'\0'))),
        'v1_digest_extra_field': content(algorithm=seq(oid(sha256_oid) + b'\x05\0\x05\0')),
        'v1_digest_missing_oid': content(algorithm=seq(b'\x05\0')),
        'v1_digest_unterminated_oid': content(algorithm=seq(tlv('06', bytes.fromhex('60864801650304020180')))),
        'v1_digest_nonminimal_oid': content(algorithm=seq(tlv('06', bytes.fromhex('80608648016503040201')))),
    })
    invalid_info = {
        'wrong_tag': tlv('31', tlv('13', b'0108') + tlv('13', b'060000')),
        'empty': seq(b''), 'missing_unicode': seq(tlv('13', b'0108')),
        'extra_child': seq(tlv('13', b'0108') + tlv('13', b'060000') + b'\x05\0'),
        'swapped_strings': seq(tlv('13', b'060000') + tlv('13', b'0108')),
    }
    for name, lds, unicode in [
        ('short_lds', b'108', b'060000'), ('long_lds', b'00108', b'060000'),
        ('empty_lds', b'', b'060000'), ('alpha_lds', b'01A8', b'060000'),
        ('zero_lds_major', b'0008', b'060000'), ('zero_lds_minor', b'0100', b'060000'),
        ('short_unicode', b'0108', b'06000'), ('long_unicode', b'0108', b'0060000'),
        ('empty_unicode', b'0108', b''), ('alpha_unicode', b'0108', b'06000A'),
        ('nonascii', b'0108', b'06000\xff'), ('control', b'0108', b'06000\0'),
    ]:
        invalid_info[name] = seq(tlv('13', lds) + tlv('13', unicode))
    for tag in ['0C', '04', '33']:
        invalid_info['lds_tag_' + tag] = seq(tlv(tag, b'' if tag == '33' else b'0108') + tlv('13', b'060000'))
        invalid_info['unicode_tag_' + tag] = seq(tlv('13', b'0108') + tlv(tag, b'' if tag == '33' else b'060000'))
    for name, value in invalid_info.items():
        contents['v1_info_' + name] = content(version_info=value)
    body = integer(1) + alg(sha256_oid) + seq(entries) + info
    contents.update({
        'v1_truncated_outer': content()[:-1],
        'v1_truncated_info': seq(body[:-1]),
        'v1_truncated_string': content(version_info=seq(tlv('13', b'0108') + b'\x13\x06' + b'06000')),
        'v1_trailing_bytes': content() + b'\x05\0',
        'v1_nonminimal_length': b'\x30\x81' + bytes([len(body)]) + body,
        'v1_nonminimal_integer': seq(b'\x02\x02\0\x01' + body[3:]),
        'v1_negative_integer': seq(b'\x02\x01\xff' + body[3:]),
        'v1_wrong_version_tag': seq(b'\x04\x01\x01' + body[3:]),
    })

    profiles = {}
    content_type = oid('2.23.136.1.1.1')
    for name, encoded_content in contents.items():
        attrs = setof(seq(oid('1.2.840.113549.1.9.3') + setof(content_type)),
                      seq(oid('1.2.840.113549.1.9.4') + setof(tlv('04', hashlib.sha256(encoded_content).digest()))))
        signature = key.sign(attrs, padding.PKCS1v15(), hashes.SHA256())
        key.public_key().verify(signature, attrs, padding.PKCS1v15(), hashes.SHA256())
        signer = seq(integer(1) + seq(cert.issuer.public_bytes() + integer(cert.serial_number))
                     + alg(sha256_oid) + b'\xA0' + attrs[1:] + alg('1.2.840.113549.1.1.11') + tlv('04', signature))
        cms = seq(oid('1.2.840.113549.1.7.2') + tlv('A0', seq(integer(3) + setof(alg(sha256_oid))
                  + seq(content_type + tlv('A0', tlv('04', encoded_content)))
                  + tlv('A0', cert.public_bytes(serialization.Encoding.DER)) + setof(signer))))
        profiles[name] = {**{field: base[field] for field in ['com', 'dg1', 'dg11']},
                          'sod': tlv('77', cms).hex(), 'content': encoded_content.hex()}
    (OUT / 'sod-version-csca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (OUT / 'sod-version-passports.json').write_text(json.dumps(profiles, indent=2) + '\n')
    print('Generated synthetic SOD version fixtures; original regression fixtures preserved; private keys not saved.')


if __name__ == '__main__':
    main()
