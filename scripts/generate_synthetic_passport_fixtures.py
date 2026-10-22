#!/usr/bin/env python3
"""Generate public test artifacts only. Requires cryptography; never saves private keys.

This is an independent oracle: no NFCPassportReader/OpenSSL wrapper is called.
Certificates identify fictitious test authorities and are NOT production trust anchors.
Run from the repository root. Tests consume committed output without Python/network.
"""
import datetime
import hashlib
import json
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.x509.oid import NameOID

OUT = Path(__file__).resolve().parents[1] / 'Tests/NFCPassportReaderTests/Fixtures'

def tlv(tag, data):
    length = len(data)
    n = length.to_bytes(max(1, (length.bit_length() + 7) // 8), 'big')
    return bytes.fromhex(tag) + (bytes([length]) if length < 128 else bytes([128 + len(n)]) + n) + data

def seq(data): return tlv('30', data)
def integer(n):
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), 'big')
    return tlv('02', (b'\0' if raw[0] & 128 else b'') + raw)
def oid(value):
    parts = [int(x) for x in value.split('.')]
    data = bytes([parts[0] * 40 + parts[1]])
    for n in parts[2:]:
        enc = [n & 127]; n >>= 7
        while n: enc.insert(0, 128 | (n & 127)); n >>= 7
        data += bytes(enc)
    return tlv('06', data)
def alg(value): return seq(oid(value) + b'\x05\0')
def setof(*values): return tlv('31', b''.join(sorted(values)))
def checksum(value): return str(sum((0 if c == '<' else int(c) if c.isdigit() else ord(c) - 55) * [7, 3, 1][i % 3] for i, c in enumerate(value)) % 10)

def certificate(key, name, issuer=None, signer=None, ca=False, expired=False):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    begin = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    end = datetime.datetime(2021 if expired else 2099, 1, 1, tzinfo=datetime.timezone.utc)
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer.subject if issuer else subject)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(begin).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca,
            encipher_only=None, decipher_only=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key((signer or key).public_key()), critical=False)
        .sign(signer or key, hashes.SHA256()))

def main():
    OUT.mkdir(exist_ok=True)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = certificate(root_key, 'SYNTHETIC TEST CSCA', ca=True)
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other = certificate(other_key, 'UNRELATED SYNTHETIC CSCA', ca=True)
    (OUT / 'synthetic-csca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (OUT / 'unrelated-csca.pem').write_bytes(other.public_bytes(serialization.Encoding.PEM))
    doc, birth, expiry, optional = 'TEST00001', '700101', '300101', '<' * 14
    second = doc + checksum(doc) + 'UTO' + birth + checksum(birth) + 'X' + expiry + checksum(expiry) + optional + checksum(optional)
    second += checksum(second[:10] + second[13:20] + second[21:43])
    mrz = ('P<UTO' + 'SYNTHETIC<<TEST').ljust(44, '<') + second
    assert len(mrz) == 88
    dg1 = tlv('61', tlv('5F1F', mrz.encode('ascii')))
    dg11 = tlv('6B', tlv('5C', bytes.fromhex('5F0E')) + tlv('5F0E', b'SYNTHETIC<<TEST'))
    com = tlv('60', tlv('5F01', b'0107') + tlv('5F36', b'040000') + tlv('5C', bytes.fromhex('616B')))
    content_type = oid('2.23.136.1.1.1')
    profiles = {}
    for profile in ['rsa_sha256', 'ec_sha384', 'rsa_pss_sha256', 'rsa_sha512_dg', 'expired_signer']:
        is_ec = profile == 'ec_sha384'
        key = ec.generate_private_key(ec.SECP384R1()) if is_ec else rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = certificate(key, 'SYNTHETIC TEST DOCUMENT SIGNER', root, root_key, expired=profile == 'expired_signer')
        digest = hashes.SHA384() if is_ec else hashes.SHA256()
        digest_oid = '2.16.840.1.101.3.4.2.' + ('2' if is_ec else '1')
        group_hash = 'sha512' if profile == 'rsa_sha512_dg' else 'sha256'
        group_oid = '2.16.840.1.101.3.4.2.' + ('3' if group_hash == 'sha512' else '1')
        content = seq(integer(0) + alg(group_oid) + seq(b''.join(seq(integer(i) + tlv('04', hashlib.new(group_hash, value).digest())) for i, value in [(1, dg1), (11, dg11)])))
        attrs = setof(seq(oid('1.2.840.113549.1.9.3') + setof(content_type)),
                      seq(oid('1.2.840.113549.1.9.4') + setof(tlv('04', hashlib.new(digest.name, content).digest()))))
        if is_ec:
            signature = key.sign(attrs, ec.ECDSA(digest)); signature_alg = seq(oid('1.2.840.10045.4.3.3'))
        elif profile == 'rsa_pss_sha256':
            signature = key.sign(attrs, padding.PSS(mgf=padding.MGF1(digest), salt_length=32), digest)
            params = seq(tlv('A0', alg(digest_oid)) + tlv('A1', seq(oid('1.2.840.113549.1.1.8') + alg(digest_oid))) + tlv('A2', integer(32)))
            signature_alg = seq(oid('1.2.840.113549.1.1.10') + params)
        else:
            signature = key.sign(attrs, padding.PKCS1v15(), digest); signature_alg = alg('1.2.840.113549.1.1.11')
        signer = seq(integer(1) + seq(cert.issuer.public_bytes() + integer(cert.serial_number)) + alg(digest_oid) + b'\xA0' + attrs[1:] + signature_alg + tlv('04', signature))
        cms = seq(oid('1.2.840.113549.1.7.2') + tlv('A0', seq(integer(3) + setof(alg(digest_oid)) + seq(content_type + tlv('A0', tlv('04', content))) + tlv('A0', cert.public_bytes(serialization.Encoding.DER)) + setof(signer))))
        profiles[profile] = {'com': com.hex(), 'dg1': dg1.hex(), 'dg11': dg11.hex(), 'sod': tlv('77', cms).hex(), 'content': content.hex()}
    (OUT / 'signed-passports.json').write_text(json.dumps(profiles, indent=2) + '\n')
    print('Generated five synthetic signed-document profiles; private keys were not saved.')

if __name__ == '__main__': main()
