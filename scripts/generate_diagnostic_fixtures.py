#!/usr/bin/env python3
"""Independent synthetic diagnostic regression corpus. Never persists private keys.

Uses Python cryptography to sign CMS attributes; no reader/OpenSSL wrapper is used.
Existing signed-passports.json is unchanged. New CSCA is test-only.
"""
import hashlib
import json
from generate_synthetic_passport_fixtures import OUT, tlv, seq, integer, oid, alg, setof, certificate
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, utils


def main():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = certificate(root_key, 'SYNTHETIC DIAGNOSTICS CSCA', ca=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = certificate(key, 'SYNTHETIC DIAGNOSTICS SIGNER', root, root_key)
    (OUT / 'diagnostic-csca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    base = json.loads((OUT / 'signed-passports.json').read_text())['rsa_sha256']
    groups = [(1, bytes.fromhex(base['dg1'])), (11, bytes.fromhex(base['dg11']))]
    digest_oid = '2.16.840.1.101.3.4.2.1'
    content_type = oid('2.23.136.1.1.1')
    profiles = {}
    for profile in ['v0', 'v1', 'rsa_encryption', 'unknown_digest', 'unknown_signature', 'bad_hash_length', 'bad_lds_tag']:
        group_oid = '1.2.3.4.5.6' if profile == 'unknown_digest' else digest_oid
        entries = seq(b''.join(seq(integer(i) + tlv('04', hashlib.sha256(data).digest()[:31 if profile == 'bad_hash_length' else 32])) for i, data in groups))
        info = seq(tlv('13', b'0108') + tlv('13', b'060000')) if profile == 'v1' else b''
        content = tlv('31' if profile == 'bad_lds_tag' else '30', integer(1 if profile == 'v1' else 0) + alg(group_oid) + entries + info)
        attrs = setof(seq(oid('1.2.840.113549.1.9.3') + setof(content_type)),
                      seq(oid('1.2.840.113549.1.9.4') + setof(tlv('04', hashlib.sha256(content).digest()))))
        signature = key.sign(attrs, padding.PKCS1v15(), hashes.SHA256())
        # Independently verify every signature before packaging even deliberately unsupported identifiers.
        key.public_key().verify(signature, attrs, padding.PKCS1v15(), hashes.SHA256())
        signature_oid = '1.2.840.113549.1.1.1' if profile == 'rsa_encryption' else '1.2.3.4.5.6' if profile == 'unknown_signature' else '1.2.840.113549.1.1.11'
        signer = seq(integer(1) + seq(cert.issuer.public_bytes() + integer(cert.serial_number)) + alg(digest_oid) + b'\xA0' + attrs[1:] + alg(signature_oid) + tlv('04', signature))
        cms = seq(oid('1.2.840.113549.1.7.2') + tlv('A0', seq(integer(3) + setof(alg(digest_oid)) + seq(content_type + tlv('A0', tlv('04', content))) + tlv('A0', cert.public_bytes(serialization.Encoding.DER)) + setof(signer))))
        profiles[profile] = {**{name: base[name] for name in ['com', 'dg1', 'dg11']}, 'sod': tlv('77', cms).hex(), 'content': content.hex()}
    aa_key = ec.generate_private_key(ec.SECP256R1())
    challenge = bytes(range(8))
    signature = aa_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
    aa_key.public_key().verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(signature)
    profiles['active_authentication'] = {
        'dg15': tlv('6F', aa_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hex(),
        'challenge': challenge.hex(), 'response': (r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).hex()
    }
    (OUT / 'diagnostic-passports.json').write_text(json.dumps(profiles, indent=2) + '\n')
    print('Generated synthetic diagnostic fixtures; private keys were not saved.')


if __name__ == '__main__':
    main()
