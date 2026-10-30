#!/usr/bin/env python3
"""Synthetic ICAO 39794-5 Annex A encodings and independent signed DG2 fixtures.

Schema facts from ICAO's August 2023 application profile. No reader encoder,
real face image, identity, private key or third-party passport fixture is used.
See THIRD_PARTY_NOTICES.md for schema attribution.
"""
import hashlib
import io
import json
from PIL import Image
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from generate_synthetic_passport_fixtures import OUT, tlv, seq, integer, oid, alg, setof, certificate


def implicit_integer(tag, value):
    raw = integer(value)
    return bytes.fromhex(tag) + raw[1:]

def main():
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root = certificate(root_key, 'SYNTHETIC FACE FORMAT ROOT', ca=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = certificate(key, 'SYNTHETIC FACE FORMAT SIGNER', root, root_key)
    base = json.loads((OUT/'diagnostic-passports.json').read_text())['v1']
    pixels = Image.new('RGB', (16, 20), (40, 100, 160))  # A solid rectangle, never a person's face.
    jpeg = io.BytesIO(); pixels.save(jpeg, format='JPEG')
    jp2 = io.BytesIO(); pixels.save(jp2, format='JPEG2000', irreversible=True)
    jp2_lossless = io.BytesIO(); pixels.save(jp2_lossless, format='JPEG2000', irreversible=False)
    version = tlv('A0', implicit_integer('80', 3) + implicit_integer('81', 2019))
    sizes = tlv('A7', implicit_integer('80', 16) + implicit_integer('81', 20))
    kind = tlv('A1', tlv('A1', implicit_integer('80', 0)))
    ctype = oid('2.23.136.1.1.1'); sha = '2.16.840.1.101.3.4.2.1'

    def face(data=jpeg.getvalue(), format=2, ver=version, size=sizes, extensions=False,
             representations=1, info_extra=b'', record_extra=b'', block_extra=b'', wrapper_tag='A1'):
        information = tlv('A0', implicit_integer('80', format)) + kind + size + info_extra
        representation = implicit_integer('80', 0) + tlv('A1', tlv('A0', tlv('A0',
            tlv('80', data) + tlv('A1', information) + block_extra))) + record_extra
        if extensions: representation += tlv('AA', implicit_integer('80', 17))
        encoded = ver + tlv('A1', b''.join(seq(representation) for _ in range(representations)))
        if extensions: encoded += tlv('A2', implicit_integer('80', 9))
        return tlv(wrapper_tag, tlv('65', encoded))

    def template(payload):
        header = tlv('A1', tlv('80', b'\x01') + tlv('81', b'\x02') + tlv('87', b'\x01\x01') + tlv('88', b'\0\x01'))
        return tlv('7F60', header + tlv('7F2E', payload))

    def dg2(payloads): return tlv('75', tlv('7F61', integer(len(payloads)) + b''.join(template(p) for p in payloads)))

    cases = {
        'jpeg': ([face()], True), 'jpeg2000_lossy': ([face(jp2.getvalue(), 3)], True),
        'jpeg2000_lossless': ([face(jp2_lossless.getvalue(), 4)], True),
        'optional_size_absent': ([face(size=b'')], True),
        'future_extensions': ([face(extensions=True)], True),
        'future_version': ([face(ver=tlv('A0', implicit_integer('80', 4) + implicit_integer('81', 2030)))], True),
        'multiple_templates': ([face(), face(jp2.getvalue(), 3)], True),
        'zero_representations': ([face(representations=0)], False),
        'multiple_representations': ([face(representations=2)], False),
        'wrong_format': ([face(format=3)], False), 'png_excluded_by_profile': ([face(format=5)], False),
        'missing_version': ([face(ver=b'')], False),
        'bad_generation': ([face(ver=tlv('A0', implicit_integer('80', 2) + implicit_integer('81', 2019)))], False),
        'missing_year': ([face(ver=tlv('A0', implicit_integer('80', 3)))], False),
        'duplicate_version': ([face(ver=version+version)], False),
        'bad_wrapper': ([face(wrapper_tag='A2')], False),
        'oversize_width': ([face(size=tlv('A7', implicit_integer('80', 20001)+implicit_integer('81', 20)))], False),
        'missing_height': ([face(size=tlv('A7', implicit_integer('80', 16)))], False),
        'trailing_size': ([face(size=tlv('A7', implicit_integer('80', 16)+implicit_integer('81', 20)+implicit_integer('82', 1)))], False),
        'duplicate_format': ([face(info_extra=tlv('A0', implicit_integer('80', 2)))], False),
        'empty_image': ([face(data=b'')], False),
        'wrong_image': ([face(data=b'\x89PNG\r\n\x1a\n')], False),
        'negative_session': ([face(record_extra=tlv('85', b'\xff'))], False),
        'truncated': ([face()[:-1]], False),
        'trailing': ([face()+b'\x05\0'], False),
    }
    profiles = {}
    for name, (blocks, valid) in cases.items():
        group = dg2(blocks)
        dg1 = bytes.fromhex(base['dg1'])
        content = seq(integer(1) + alg(sha) + seq(b''.join(seq(integer(n)+tlv('04', hashlib.sha256(b).digest())) for n,b in [(1,dg1),(2,group)])) + seq(tlv('13', b'0108')+tlv('13',b'060000')))
        attrs = setof(seq(oid('1.2.840.113549.1.9.3')+setof(ctype)), seq(oid('1.2.840.113549.1.9.4')+setof(tlv('04',hashlib.sha256(content).digest()))))
        signature = key.sign(attrs,padding.PKCS1v15(),hashes.SHA256())
        signer = seq(integer(1)+seq(cert.issuer.public_bytes()+integer(cert.serial_number))+alg(sha)+b'\xA0'+attrs[1:]+alg('1.2.840.113549.1.1.11')+tlv('04',signature))
        cms = seq(oid('1.2.840.113549.1.7.2')+tlv('A0',seq(integer(3)+setof(alg(sha))+seq(ctype+tlv('A0',tlv('04',content)))+tlv('A0',cert.public_bytes(serialization.Encoding.DER))+setof(signer))))
        com = tlv('60',tlv('5F01',b'0108')+tlv('5F36',b'060000')+tlv('5C',bytes.fromhex('6175')))
        profiles[name] = {'dg1':base['dg1'],'dg2':group.hex(),'com':com.hex(),'sod':tlv('77',cms).hex(),'valid':valid,'images':len(blocks)}
    (OUT/'face-profiles.json').write_text(json.dumps(profiles,indent=2)+'\n')
    (OUT/'face-profile-csca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    print('Generated synthetic face encoding profiles; no real photos or private keys saved.')

if __name__ == '__main__': main()
