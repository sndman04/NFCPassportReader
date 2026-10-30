#!/usr/bin/env python3
"""Public domain parameters generated with external OpenSSL CLI from ICAO Part 11 Table 12.

No key generation, secret, passport content or reader encoding code is used.
"""
import base64
import json
import subprocess
from generate_synthetic_passport_fixtures import OUT

CURVES = ['prime192v1','brainpoolP192r1','secp224r1','brainpoolP224r1','prime256v1',
          'brainpoolP256r1','brainpoolP320r1','secp384r1','brainpoolP384r1','brainpoolP512r1','secp521r1']

def main():
    profiles = {}
    for index, name in enumerate(CURVES, 8):
        data = subprocess.check_output(['openssl','ecparam','-name',name,'-param_enc','explicit','-outform','DER'])
        profiles[str(index)] = data.hex()
    for index in range(3):
        pem = subprocess.check_output(['openssl','genpkey','-genparam','-algorithm','DHX','-pkeyopt',f'dh_rfc5114:{index+1}'])
        data = base64.b64decode(b''.join(line for line in pem.splitlines() if not line.startswith(b'-----')))
        profiles[str(index)] = data.hex()
    (OUT/'pace-explicit-parameters.json').write_text(json.dumps(profiles,indent=2)+'\n')
    print('Generated 14 public explicit domain parameter profiles; no secrets generated.')

if __name__ == '__main__': main()
