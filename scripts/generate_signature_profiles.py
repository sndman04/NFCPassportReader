#!/usr/bin/env python3
"""Independent CMS/PSS corpus using Python cryptography; no private keys are saved."""
import hashlib
import json
import subprocess
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa, ec
from generate_synthetic_passport_fixtures import OUT, tlv, seq, integer, oid, alg, setof, certificate

DIGESTS = {'sha1': ('1.3.14.3.2.26', hashes.SHA1), 'sha224': ('2.16.840.1.101.3.4.2.4', hashes.SHA224),
           'sha256': ('2.16.840.1.101.3.4.2.1', hashes.SHA256), 'sha384': ('2.16.840.1.101.3.4.2.2', hashes.SHA384),
           'sha512': ('2.16.840.1.101.3.4.2.3', hashes.SHA512)}
PSS = '1.2.840.113549.1.1.10'
MGF = '1.2.840.113549.1.1.8'

def pss_params(digest, mgf, salt):
    return seq((tlv('A0', alg(DIGESTS[digest][0])) if digest != 'sha1' else b'')
               + (tlv('A1', seq(oid(MGF) + alg(DIGESTS[mgf][0]))) if mgf != 'sha1' else b'')
               + (tlv('A2', integer(salt)) if salt != 20 else b''))

def children(data):
    def item(offset):
        start = offset
        offset += 1
        length = data[offset]; offset += 1
        if length & 128:
            size = length & 127
            length = int.from_bytes(data[offset:offset+size], 'big'); offset += size
        return start, offset, offset+length
    _, begin, end = item(0)
    result = []
    while begin < end:
        start, _, stop = item(begin)
        result.append(data[start:stop]); begin = stop
    assert begin == end
    return result

def replace_spki_algorithm(cert, algorithm, issuer_key):
    tbs = children(cert.tbs_certificate_bytes)
    spki = children(tbs[6])
    tbs[6] = seq(algorithm + spki[1])
    encoded_tbs = seq(b''.join(tbs))
    signature = issuer_key.sign(encoded_tbs, padding.PKCS1v15(), hashes.SHA256())
    return x509.load_der_x509_certificate(seq(encoded_tbs + alg('1.2.840.113549.1.1.11') + tlv('03', b'\0'+signature)))

def main():
    rk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = certificate(rk, 'SYNTHETIC CMS PROFILE ROOT', ca=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = certificate(key, 'SYNTHETIC CMS SIGNER', root, rk)
    extra_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    extra = certificate(extra_key, 'SYNTHETIC EXTRA CERTIFICATE', root, rk)
    bad_root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    bad_root = certificate(bad_root_key, 'SYNTHETIC UNTRUSTED ROOT', ca=True)
    untrusted = certificate(key, 'SYNTHETIC UNTRUSTED SIGNER', bad_root, bad_root_key)
    base = json.loads((OUT/'diagnostic-passports.json').read_text())['v1']
    content = bytes.fromhex(base['content'])
    ctype = oid('2.23.136.1.1.1')
    profiles = {}

    def signer(digest='sha256', mgf='sha256', salt=32, parameters=None, content_digest=None, signer_cert=cert,
               signer_key=key, ski=False, attrs_type=ctype, duplicate_digest=False, sid_override=None, corrupt=False):
        content_digest = content_digest or digest
        hash_attr = seq(oid('1.2.840.113549.1.9.4') + setof(tlv('04', hashlib.new(content_digest, content).digest())))
        attrs = setof(seq(oid('1.2.840.113549.1.9.3') + setof(attrs_type)), hash_attr,
                      *([hash_attr] if duplicate_digest else []))
        pad = padding.PSS(mgf=padding.MGF1(DIGESTS[mgf][1]()), salt_length=salt)
        signature = signer_key.sign(attrs, pad, DIGESTS[digest][1]())
        signer_key.public_key().verify(signature, attrs, pad, DIGESTS[digest][1]())
        if corrupt: signature = signature[:-1] + bytes([signature[-1] ^ 1])
        sid = tlv('80', signer_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest) if ski else seq(signer_cert.issuer.public_bytes() + integer(signer_cert.serial_number))
        algorithm = seq(oid(PSS) + (pss_params(digest, mgf, salt) if parameters is None else parameters))
        return seq(integer(3 if ski else 1) + (sid_override or sid) + alg(DIGESTS[content_digest][0])
                   + b'\xA0' + attrs[1:] + algorithm + tlv('04', signature)), alg(DIGESTS[content_digest][0])

    def add(name, signers=None, certs=None, valid=True, trusted=True, cms=True, digest_set=None):
        signers = signers or [signer()]
        certificates = certs if certs is not None else [cert]
        cms_der = seq(oid('1.2.840.113549.1.7.2') + tlv('A0', seq(integer(3)
            + (digest_set if digest_set is not None else setof(*sorted(set(d for _, d in signers))))
            + seq(ctype + tlv('A0', tlv('04', content)))
            + tlv('A0', b''.join(c.public_bytes(serialization.Encoding.DER) for c in certificates))
            + setof(*(s for s, _ in signers)))))
        profiles[name] = {**{k: base[k] for k in ['com', 'dg1', 'dg11', 'content']}, 'sod': tlv('77', cms_der).hex(),
                          'valid': valid, 'trusted': trusted and valid, 'cms': cms and valid}

    for digest in DIGESTS:
        for mgf in DIGESTS:
            for salt in [0, 20, 32, 64]:
                add(f'pss_{digest}_{mgf}_{salt}', [signer(digest, mgf, salt)])
    add('pss_different_content_hash', [signer(content_digest='sha512')], cms=False)
    add('ski', [signer(ski=True)])
    add('extra_first', certs=[extra, cert])
    add('extra_last', certs=[cert, extra])
    add('root_first', certs=[root, cert, extra])
    add('multiple_signers', [signer(), signer(digest='sha384', mgf='sha512', salt=48, signer_cert=extra, signer_key=extra_key, ski=True)], [extra, root, cert])
    # Untrusted actual signer with a trusted but unrelated certificate first must not acquire its trust.
    add('untrusted_signer_trusted_first', [signer(signer_cert=untrusted)], [extra, untrusted], trusted=False)
    add('multiple_one_untrusted', [signer(), signer(signer_cert=untrusted)], [cert, untrusted], trusted=False)
    add('missing_signer_certificate', certs=[extra], valid=False)
    add('sid_mismatch', [signer(sid_override=seq(extra.issuer.public_bytes() + integer(extra.serial_number)))], [cert, extra], valid=False)
    add('ski_mismatch', [signer(ski=True, sid_override=tlv('80', bytes(20)))], valid=False)
    add('corrupt_signature', [signer(corrupt=True)], valid=False)
    add('multiple_bad_signature', [signer(), signer(signer_cert=extra, signer_key=extra_key, corrupt=True)], [cert, extra], valid=False)
    add('wrong_content_type', [signer(attrs_type=oid('1.2.3.4'))], valid=False)
    add('duplicate_message_digest', [signer(duplicate_digest=True)], valid=False)
    add('missing_digest_algorithm', digest_set=setof(alg(DIGESTS['sha512'][0])), valid=False)
    invalid = {
        'absent': b'', 'null': b'\x05\0', 'negative_salt': seq(tlv('A2', b'\x02\x01\xff')),
        'overflow_salt': seq(tlv('A2', integer(1 << 80))),
        'duplicate_salt': seq(tlv('A2', integer(32)) * 2),
        'reordered': seq(tlv('A2', integer(32)) + tlv('A0', alg(DIGESTS['sha256'][0]))),
        'unknown_field': seq(tlv('A4', integer(1))),
        'bad_trailer': seq(tlv('A3', integer(2))),
        'wrong_hash': pss_params('sha384', 'sha256', 32),
        'wrong_mgf_hash': pss_params('sha256', 'sha512', 32),
        'wrong_salt': pss_params('sha256', 'sha256', 20),
        'unknown_hash': seq(tlv('A0', alg('1.2.3.4'))),
        'unknown_mgf': seq(tlv('A1', seq(oid('1.2.3.4') + alg(DIGESTS['sha256'][0])))),
        'mgf_without_hash': seq(tlv('A1', seq(oid(MGF)))),
        'nonminimal_salt': seq(tlv('A2', b'\x02\x02\0\x20')),
        'truncated': b'\x30\x03\xA2\x02\x02',
    }
    # Truncated ASN.1 is checked separately at the outer parser boundary.
    for name, params in invalid.items():
        if name != 'truncated': add('invalid_pss_' + name, [signer(parameters=params)], valid=False)
    # RSA-PSS key constraints in SubjectPublicKeyInfo must be enforced, not only the signature parameters.
    restricted = replace_spki_algorithm(cert, seq(oid(PSS) + pss_params('sha256', 'sha256', 32)), rk)
    add('restricted_pss_key', [signer(signer_cert=restricted)], [restricted])
    add('restricted_pss_salt_too_short', [signer(signer_cert=restricted, salt=20)], [restricted], valid=False)
    add('restricted_pss_wrong_digest', [signer(signer_cert=restricted, digest='sha384')], [restricted], valid=False)
    add('restricted_pss_wrong_mgf', [signer(signer_cert=restricted, mgf='sha384')], [restricted], valid=False)

    dsa_key = dsa.generate_private_key(key_size=2048)
    dsa_cert = certificate(dsa_key, 'SYNTHETIC DSA SIGNER', root, rk)
    for family in ['dsa', 'ec_explicit']:
        for index, digest in enumerate(['sha224','sha256','sha384','sha512'], 1):
            if family == 'dsa':
                signing_key, signing_cert = dsa_key, dsa_cert
                signature_oid = '2.16.840.1.101.3.4.3.' + str(index)
            else:
                curve = {'sha224': ec.SECP224R1, 'sha256': ec.SECP256R1, 'sha384': ec.SECP384R1, 'sha512': ec.SECP521R1}[digest]
                curve_name = {'sha224': 'secp224r1','sha256': 'prime256v1','sha384': 'secp384r1','sha512': 'secp521r1'}[digest]
                signing_key = ec.generate_private_key(curve())
                signing_cert = certificate(signing_key, 'SYNTHETIC EXPLICIT EC SIGNER', root, rk)
                explicit = subprocess.check_output(['openssl','ecparam','-name',curve_name,'-param_enc','explicit','-outform','DER'])
                signing_cert = replace_spki_algorithm(signing_cert, seq(oid('1.2.840.10045.2.1')+explicit), rk)
                signature_oid = '1.2.840.10045.4.3.' + str(index)
            attrs = setof(seq(oid('1.2.840.113549.1.9.3')+setof(ctype)),
                          seq(oid('1.2.840.113549.1.9.4')+setof(tlv('04',hashlib.new(digest,content).digest()))))
            signing_algorithm = DIGESTS[digest][1]() if family == 'dsa' else ec.ECDSA(DIGESTS[digest][1]())
            signature = signing_key.sign(attrs, signing_algorithm)
            signing_key.public_key().verify(signature, attrs, signing_algorithm)
            digest_algorithm = alg(DIGESTS[digest][0])
            encoded = seq(integer(1)+seq(signing_cert.issuer.public_bytes()+integer(signing_cert.serial_number))
                         +digest_algorithm+b'\xA0'+attrs[1:]+seq(oid(signature_oid))+tlv('04',signature))
            add(f'{family}_{digest}', [(encoded,digest_algorithm)], [signing_cert])
    (OUT/'signature-profiles.json').write_text(json.dumps(profiles, indent=2) + '\n')
    (OUT/'signature-profile-csca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    print('Generated independent synthetic CMS signature profiles; private keys not saved.')

if __name__ == '__main__': main()
