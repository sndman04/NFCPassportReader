#!/usr/bin/env python3
"""Independent synthetic AA responses per ICAO Part 11 §6.1.2; no private keys saved."""
import hashlib
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from generate_synthetic_passport_fixtures import OUT, tlv, seq, integer, oid, setof


def main():
    challenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'
    profiles = {}
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = rsa_key.private_numbers()
    spki = rsa_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    def rsa_profile(name, digest, trailer, header=0x6a, complement=False, wrong_digest=False):
        size = 256
        recovered = bytes([header]) + bytes([0x45]) * (size-1-len(trailer)-hashlib.new(digest).digest_size)
        hashed = hashlib.new(digest, recovered[1:]+challenge).digest()
        if wrong_digest: hashed = bytes([hashed[0]^1])+hashed[1:]
        block = recovered+hashed+trailer
        signature = pow(int.from_bytes(block,'big'), numbers.d, numbers.public_numbers.n)
        if complement: signature = numbers.public_numbers.n-signature
        profiles[name] = {'dg15':tlv('6F',spki).hex(),'dg14':'','challenge':challenge.hex(),
                          'signature':signature.to_bytes(size,'big').hex(), 'valid':header==0x6a and not wrong_digest and (trailer==b'\xbc' or trailer[-1]==0xcc)}

    for digest, code in [('sha1',0x33),('sha224',0x38),('sha256',0x34),('sha384',0x36),('sha512',0x35)]:
        for complement in [False, True]:
            rsa_profile(f'rsa_{digest}_{complement}',digest,bytes([code,0xcc]),complement=complement)
        rsa_profile(f'rsa_bad_header_{digest}',digest,bytes([code,0xcc]),header=0x4a)
        rsa_profile(f'rsa_bad_hash_{digest}',digest,bytes([code,0xcc]),wrong_digest=True)
        rsa_profile(f'rsa_bad_trailer_{digest}',digest,bytes([code]))
    rsa_profile('rsa_implicit_sha1','sha1',b'\xbc')
    for curve, algorithm, suffix in [(ec.SECP224R1,hashes.SHA224,2),(ec.SECP256R1,hashes.SHA256,3),
                                      (ec.SECP384R1,hashes.SHA384,4),(ec.SECP521R1,hashes.SHA512,5)]:
        key = ec.generate_private_key(curve())
        spki = key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        der = key.sign(challenge,ec.ECDSA(algorithm()))
        key.public_key().verify(der,challenge,ec.ECDSA(algorithm()))
        r,s = decode_dss_signature(der); size=(key.key_size+7)//8
        signature = r.to_bytes(size,'big')+s.to_bytes(size,'big')
        dg14 = tlv('6E',setof(seq(oid('2.23.136.1.1.5')+integer(1)+oid(f'0.4.0.127.0.7.1.1.4.1.{suffix}'))))
        base = {'dg15':tlv('6F',spki).hex(),'dg14':dg14.hex(),'challenge':challenge.hex(),'signature':signature.hex(),'valid':True}
        profiles[f'ec_{algorithm.name}'] = base
        profiles[f'ec_missing_algorithm_{algorithm.name}'] = {**base,'dg14':'','valid':False}
        profiles[f'ec_unknown_algorithm_{algorithm.name}'] = {**base,'dg14':tlv('6E',setof(seq(oid('2.23.136.1.1.5')+integer(1)+oid('1.2.3.4')))).hex(),'valid':False}
        profiles[f'ec_corrupted_{algorithm.name}'] = {**base,'signature':(signature[:-1]+bytes([signature[-1]^1])).hex(),'valid':False}
    for name, algorithm, suffix in [('weak_sha1',hashes.SHA1,1),('oversized_hash',hashes.SHA512,5)]:
        key=ec.generate_private_key(ec.SECP256R1())
        spki=key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        r,s=decode_dss_signature(key.sign(challenge,ec.ECDSA(algorithm())))
        signature=r.to_bytes(32,'big')+s.to_bytes(32,'big')
        profiles[name]={'dg15':tlv('6F',spki).hex(),'dg14':tlv('6E',setof(seq(oid('2.23.136.1.1.5')+integer(1)+oid(f'0.4.0.127.0.7.1.1.4.1.{suffix}')))).hex(),'challenge':challenge.hex(),'signature':signature.hex(),'valid':False}
    (OUT/'active-authentication-profiles.json').write_text(json.dumps(profiles,indent=2)+'\n')
    print('Generated synthetic RSA/ECDSA Active Authentication profiles; private keys not saved.')

if __name__ == '__main__': main()
