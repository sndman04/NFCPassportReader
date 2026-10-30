#!/usr/bin/env python3
"""Synthetic signed SOD and CRL corpus, with offline verification and no saved private keys."""
import datetime
import hashlib
import json
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ObjectIdentifier
from generate_synthetic_passport_fixtures import OUT, tlv, seq, integer, oid, alg, setof, certificate


def main():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = certificate(key,'SYNTHETIC REVOCATION ROOT',ca=True)
    skey = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    signer = certificate(skey,'SYNTHETIC REVOCATION SIGNER',root,key)
    wrong_key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    base = json.loads((OUT/'diagnostic-passports.json').read_text())['v1']
    content=bytes.fromhex(base['content']); ctype=oid('2.23.136.1.1.1'); sha='2.16.840.1.101.3.4.2.1'
    attrs=setof(seq(oid('1.2.840.113549.1.9.3')+setof(ctype)),seq(oid('1.2.840.113549.1.9.4')+setof(tlv('04',hashlib.sha256(content).digest()))))
    signature=skey.sign(attrs,padding.PKCS1v15(),hashes.SHA256())
    si=seq(integer(1)+seq(signer.issuer.public_bytes()+integer(signer.serial_number))+alg(sha)+b'\xa0'+attrs[1:]+alg('1.2.840.113549.1.1.11')+tlv('04',signature))
    cms=seq(oid('1.2.840.113549.1.7.2')+tlv('A0',seq(integer(3)+setof(alg(sha))+seq(ctype+tlv('A0',tlv('04',content)))+tlv('A0',signer.public_bytes(serialization.Encoding.DER))+setof(si))))
    fixture={**base,'sod':tlv('77',cms).hex()}
    def date(year): return datetime.datetime(year,1,1,tzinfo=datetime.timezone.utc)
    def crl(revoked=False, start=2020, end=2099, rename=False, number=1, signing_key=key, bad_extension=False):
        issuer=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'SYNTHETIC RENAMED AUTHORITY')]) if rename else root.subject
        builder=(x509.CertificateRevocationListBuilder().issuer_name(issuer).last_update(date(start)).next_update(date(end))
                 .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()),False)
                 .add_extension(x509.CRLNumber(number),False))
        if revoked:
            entry=x509.RevokedCertificateBuilder().serial_number(signer.serial_number).revocation_date(date(2020)).build()
            builder=builder.add_revoked_certificate(entry)
        if bad_extension: builder=builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4'),b'\x05\0'),True)
        result=builder.sign(signing_key,hashes.SHA256())
        assert result.is_signature_valid(signing_key.public_key())
        return result
    values={'clear':(crl(),'passed'),'revoked':(crl(True),'revoked'),
            'expired':(crl(end=2021),'expiredList'),'future':(crl(start=2090),'futureList'),
            'wrong_signature':(crl(signing_key=wrong_key),'invalidList'),
            'critical_extension':(crl(bad_extension=True),'invalidList'),
            'renamed_issuer':(crl(rename=True),'passed')}
    profiles={name:{'data':value.public_bytes(serialization.Encoding.PEM).hex(),'reason':reason} for name,(value,reason) in values.items()}
    profiles['der']={'data':values['clear'][0].public_bytes(serialization.Encoding.DER).hex(),'reason':'passed'}
    older=crl(start=2020,number=1).public_bytes(serialization.Encoding.PEM)
    newer=crl(True,start=2021,number=2).public_bytes(serialization.Encoding.PEM)
    for name,data in [('latest_first',newer+older),('latest_last',older+newer)]:
        profiles[name]={'data':data.hex(),'reason':'revoked'}
    profiles['trailing_garbage']={'data':(older+b'garbage').hex(),'reason':'invalidList'}
    profiles['truncated_replacement']={'data':(older+newer[:-30]).hex(),'reason':'invalidList'}
    profiles['truncated_der']={'data':values['clear'][0].public_bytes(serialization.Encoding.DER)[:-1].hex(),'reason':'invalidList'}
    old_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    old_root=certificate(old_key,'SYNTHETIC REVOCATION ROOT',ca=True)
    link=certificate(key,'SYNTHETIC REVOCATION ROOT',old_root,old_key,ca=True)
    linked_master=(old_root.public_bytes(serialization.Encoding.PEM)+link.public_bytes(serialization.Encoding.PEM)).decode('ascii')
    no_usage=(x509.CertificateBuilder().subject_name(root.subject).issuer_name(root.issuer).public_key(key.public_key())
              .serial_number(root.serial_number).not_valid_before(date(2020)).not_valid_after(date(2099)))
    for ext in root.extensions:
        value=ext.value
        if isinstance(value,x509.KeyUsage):
            value=x509.KeyUsage(digital_signature=False,content_commitment=False,key_encipherment=False,data_encipherment=False,
                               key_agreement=False,key_cert_sign=True,crl_sign=False,encipher_only=None,decipher_only=None)
        no_usage=no_usage.add_extension(value,ext.critical)
    unauthorized=no_usage.sign(key,hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode('ascii')
    (OUT/'revocation-profiles.json').write_text(json.dumps({'passport':fixture,'profiles':profiles,'linkedMasterList':linked_master,'unauthorizedMasterList':unauthorized},indent=2)+'\n')
    (OUT/'revocation-profile-csca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    print('Generated synthetic revocation profiles; no private keys saved.')

if __name__ == '__main__': main()
