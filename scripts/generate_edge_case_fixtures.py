#!/usr/bin/env python3
"""Independent synthetic CMS/CRL edge cases. No reader code or saved private keys."""
import datetime
import hashlib
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from generate_synthetic_passport_fixtures import OUT, tlv, seq, integer, oid, alg, setof, certificate


def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = certificate(key, 'SYNTHETIC EDGE AUDIT ROOT', ca=True)
    skey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signer = certificate(skey, 'SYNTHETIC EDGE AUDIT SIGNER', root, key)
    bad_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    base = json.loads((OUT/'diagnostic-passports.json').read_text())['v1']
    sha = '2.16.840.1.101.3.4.2.1'

    def cms(content, content_type):
        ctype = oid(content_type)
        attrs = setof(seq(oid('1.2.840.113549.1.9.3')+setof(ctype)),
                      seq(oid('1.2.840.113549.1.9.4')+setof(tlv('04', hashlib.sha256(content).digest()))))
        signature = skey.sign(attrs, padding.PKCS1v15(), hashes.SHA256())
        skey.public_key().verify(signature, attrs, padding.PKCS1v15(), hashes.SHA256())
        si = seq(integer(1)+seq(signer.issuer.public_bytes()+integer(signer.serial_number))+alg(sha)
                 +b'\xa0'+attrs[1:]+alg('1.2.840.113549.1.1.11')+tlv('04', signature))
        return seq(oid('1.2.840.113549.1.7.2')+tlv('A0', seq(integer(3)+setof(alg(sha))
                   +seq(ctype+tlv('A0', tlv('04', content)))+tlv('A0', signer.public_bytes(serialization.Encoding.DER))+setof(si))))

    passport = {**base, 'sod': tlv('77', cms(bytes.fromhex(base['content']), '2.23.136.1.1.1')).hex()}
    ca_key = ec.generate_private_key(ec.SECP256R1())
    dg14 = tlv('6E', setof(seq(oid('0.4.0.127.0.7.2.2.3.2.2')+integer(1)+integer(0)),
                           seq(oid('0.4.0.127.0.7.2.2.1.2')+ca_key.public_key().public_bytes(
                               serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)+integer(0))))
    dg15 = tlv('6F', skey.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    auth_groups = [(1, bytes.fromhex(base['dg1'])), (11, bytes.fromhex(base['dg11'])), (14, dg14), (15, dg15)]
    auth_content = seq(integer(1)+alg(sha)+seq(b''.join(seq(integer(i)+tlv('04', hashlib.sha256(data).digest()))
                                                     for i, data in auth_groups))+seq(tlv('13', b'0108')+tlv('13', b'040000')))
    hidden_auth = {**base, 'dg14': dg14.hex(), 'dg15': dg15.hex(), 'content': auth_content.hex(),
                   'sod': tlv('77', cms(auth_content, '2.23.136.1.1.1')).hex()}
    aa_content = seq(integer(1)+alg(sha)+seq(b''.join(seq(integer(i)+tlv('04', hashlib.sha256(data).digest()))
                                                   for i, data in auth_groups if i != 14))+seq(tlv('13', b'0108')+tlv('13', b'040000')))
    aa_only = {**base, 'dg15': dg15.hex(), 'content': aa_content.hex(),
               'sod': tlv('77', cms(aa_content, '2.23.136.1.1.1')).hex()}
    infos = setof(seq(oid('0.4.0.127.0.7.2.2.4.6.2')+integer(2)+integer(13)))
    cards = {name: {'data': cms(infos, content_type).hex(), 'valid': name == 'security_object'}
             for name, content_type in [('security_object', '0.4.0.127.0.7.3.2.1'),
                                        ('lds_object', '2.23.136.1.1.1'), ('generic_data', '1.2.840.113549.1.7.1')]}
    def date(year): return datetime.datetime(year, 1, 1, tzinfo=datetime.timezone.utc)
    def crl(number=10, revoked=False, reason=None, issuer_entry=False, signing_key=key, start=2020):
        builder = (x509.CertificateRevocationListBuilder().issuer_name(root.subject)
                   .last_update(date(start)).next_update(date(2099))
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
                   .add_extension(x509.CRLNumber(number), False))
        if revoked or reason is not None or issuer_entry:
            entry = x509.RevokedCertificateBuilder().serial_number(signer.serial_number).revocation_date(date(2020))
            if reason is not None: entry = entry.add_extension(x509.CRLReason(reason), False)
            if issuer_entry: entry = entry.add_extension(x509.CertificateIssuer([x509.DirectoryName(root.subject)]), False)
            builder = builder.add_revoked_certificate(entry.build())
        value = builder.sign(signing_key, hashes.SHA256())
        assert value.is_signature_valid(signing_key.public_key())
        return value.public_bytes(serialization.Encoding.PEM)

    clear = crl()
    revoke = crl(revoked=True)
    invalid = crl(number=11, signing_key=bad_key)
    later_same_number = crl(start=2021)
    profiles = {'clear': {'data': clear.hex(), 'reason': 'passed'},
                'identical_duplicate': {'data': (clear+clear).hex(), 'reason': 'passed'},
                'remove_from_complete': {'data': crl(reason=x509.ReasonFlags.remove_from_crl).hex(), 'reason': 'invalidList'},
                'indirect_entry': {'data': crl(issuer_entry=True).hex(), 'reason': 'invalidList'},
                'ordinary_reason': {'data': crl(reason=x509.ReasonFlags.key_compromise).hex(), 'reason': 'revoked'}}
    for name, a, b in [('conflicting_number', clear, revoke), ('invalid_newer', clear, invalid),
                       ('reused_number', clear, later_same_number)]:
        for suffix, data in [('forward', a+b), ('reverse', b+a)]:
            profiles[f'{name}_{suffix}'] = {'data': data.hex(), 'reason': 'invalidList'}
    (OUT/'edge-case-profiles.json').write_text(json.dumps({'passport': passport, 'hiddenAuth': hidden_auth, 'aaOnly': aa_only, 'root': root.public_bytes(serialization.Encoding.PEM).decode(),
                                                         'crls': profiles, 'cardSecurity': cards}, indent=2)+'\n')
    print('Generated independent synthetic edge cases; no private keys saved.')

if __name__ == '__main__': main()
