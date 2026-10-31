#!/usr/bin/env python3
"""Fetch pinned public sources and run the reviewed synthetic Proxmark3 generator.

Unlike fetch_external_corpora.py, this command deliberately executes a small,
reviewed upstream generator in a fresh temporary directory. No code is imported
into the library; generated private keys are never saved. Requires cryptography
and Pillow. asn1crypto is loaded from a hash-pinned pure-Python wheel.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / 'tmp/passport-samples/cache'
OUT = ROOT / 'Tests/NFCPassportReaderTests/Fixtures/ExternalPassports'


def fetch(item):
    repository = item.get('repository')
    name = repository.split('/')[-1] if repository else item['package']
    target = CACHE/name/item['path']
    if not target.exists():
        url = f"https://raw.githubusercontent.com/{repository}/{item['revision']}/{item['path']}" if repository else item['url']
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(item['size'] + 1)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    data = target.read_bytes()
    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('Pinned source integrity mismatch: ' + item['path'])
    return target


def der(data):
    """Independent bounded TLV inspection; no passport values are printed."""
    if len(data) < 2:
        raise ValueError('Truncated input')
    offset = 1
    tag = data[0]
    if tag & 31 == 31:
        while True:
            tag = tag * 256 + data[offset]
            offset += 1
            if not data[offset-1] & 128:
                break
    size = data[offset]
    offset += 1
    if size & 128:
        count = size & 127
        if count == 0 or count > 4 or offset + count > len(data):
            raise ValueError('Invalid length')
        size = int.from_bytes(data[offset:offset+count], 'big')
        offset += count
    if offset + size > len(data):
        raise ValueError('Truncated value')
    return tag, data[offset:offset+size], data[:offset+size], data[offset+size:]


def children(data):
    values = []
    while data:
        tag, value, encoded, data = der(data)
        values.append((tag, value, encoded))
    return values


def inspect(files):
    report = {'fileCount': len(files), 'hasSOD': 'sod' in files}
    if 'sod' not in files:
        return report
    _, body, _, trailing = der(bytes.fromhex(files['sod']))
    assert not trailing
    container = children(der(body)[1])
    signed = children(der(container[1][1])[1])
    encapsulated = children(signed[2][1])
    content = der(encapsulated[1][1])[1]
    fields = children(der(content)[1])
    assert children(fields[1][1])[0][2].hex() == '0609608648016503040201'  # SHA-256.
    mismatches = []
    missing = []
    for entry in children(fields[2][1]):
        identifier, digest = children(entry[1])
        number = int.from_bytes(identifier[1], 'big')
        group = files.get(f'dg{number}')
        if group is None:
            missing.append(number)
        elif hashlib.sha256(bytes.fromhex(group)).digest() != digest[1]:
            mismatches.append(number)
    openssl = shutil.which('openssl', path='/opt/homebrew/bin:' + os.environ.get('PATH', ''))
    result = subprocess.run([openssl, 'cms', '-verify', '-inform', 'DER', '-noverify', '-binary'],
                            input=body, capture_output=True, check=False)
    report.update({'cmsSignatureVerified': result.returncode == 0, 'cmsVersion': int.from_bytes(signed[0][1], 'big'),
                   'icaosodContentType': encapsulated[0][2].hex() == '0606678108010101',
                   'ldsVersion': int.from_bytes(fields[0][1], 'big'), 'hashMismatches': mismatches, 'missingGroups': missing})
    return report


def main():
    manifest = json.loads((ROOT/'Tests/ExternalPassports/manifest.json').read_text())
    sources = [(item, fetch(item)) for item in manifest]
    wheel = next(path for item, path in sources if item.get('package') == 'asn1crypto')
    samples = {}
    with tempfile.TemporaryDirectory(prefix='generator-', dir=CACHE) as directory:
        stage = Path(directory)
        for item, path in sources:
            if item.get('repository') == 'RfidResearchGroup/proxmark3' and item['path'].endswith('.py'):
                relative = Path(item['path']).relative_to('tools/ePassport')
                target = stage/relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(path.read_bytes())
        env = {**os.environ, 'PYTHONPATH': str(wheel), 'PYTHONNOUSERSITE': '1'}
        result = subprocess.run([sys.executable, '-B', str(stage/'tools_make_sample.py'), str(stage/'output')],
                                cwd=stage, env=env, capture_output=True, check=False)
        if result.returncode:
            raise RuntimeError('Pinned synthetic generator failed; no source data was logged')
        for directory in sorted((stage/'output').iterdir()):
            samples[directory.name] = {'files': {path.stem.removeprefix('EF_').lower(): path.read_bytes().hex()
                                               for path in sorted(directory.glob('*.bin'))}}
    # Original signed bytes from the MIT sample; no changes or re-signing.
    specimen = next(path for item, path in sources if item['path'].endswith('emrtd-bundle.json'))
    import base64
    files = {name: base64.b64decode(value).hex() for name, value in json.loads(specimen.read_text())['lds'].items()}
    reports = {'signed_specimen': inspect(files)}
    reports.update({name: inspect(sample['files']) for name, sample in samples.items()})
    assert reports['signed_specimen']['cmsSignatureVerified'] and not reports['signed_specimen']['hashMismatches']
    assert reports['td3_utopia']['cmsSignatureVerified'] and not reports['td3_utopia']['hashMismatches']
    assert reports['td3_utopia_tampered']['cmsSignatureVerified'] and reports['td3_utopia_tampered']['hashMismatches'] == [2]
    assert not reports['td3_utopia']['icaosodContentType'] and not reports['td1_utopia_idcard']['hasSOD']
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT/'proxmark-passports.json').write_text(json.dumps(samples, separators=(',', ':'))+'\n')
    (CACHE/'independent-report.json').write_text(json.dumps(reports, indent=2)+'\n')
    print(json.dumps(reports))  # Counts, versions and outcome categories only.


if __name__ == '__main__':
    main()
