#!/usr/bin/env python3
"""Fetch pinned public test data; never execute upstream code or save generated keys.

Requires cryptography only to derive public points for published, non-secret ECDH
scalar examples. Outputs are ignored and belong only to the XCTest bundle.
"""
import concurrent.futures
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from generate_synthetic_passport_fixtures import tlv, seq, integer, oid, alg

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / 'tmp/external-corpora'
OUT = ROOT / 'Tests/NFCPassportReaderTests/Fixtures/ExternalCorpora'
DIGESTS = {'SHA-1': '1.3.14.3.2.26', 'SHA-224': '2.16.840.1.101.3.4.2.4',
           'SHA-256': '2.16.840.1.101.3.4.2.1', 'SHA-384': '2.16.840.1.101.3.4.2.2',
           'SHA-512': '2.16.840.1.101.3.4.2.3'}
EC_SIG = {'SHA-1': '1.2.840.10045.4.1', 'SHA-224': '1.2.840.10045.4.3.1',
          'SHA-256': '1.2.840.10045.4.3.2', 'SHA-384': '1.2.840.10045.4.3.3', 'SHA-512': '1.2.840.10045.4.3.4'}
DSA_SIG = {'SHA-224': '2.16.840.1.101.3.4.3.1', 'SHA-256': '2.16.840.1.101.3.4.3.2'}
CURVES = {'secp256r1': ec.SECP256R1, 'secp384r1': ec.SECP384R1, 'secp521r1': ec.SECP521R1}


def fetch(item):
    target = CACHE/item['corpus']/item['path']
    if not target.exists():
        url = f"https://raw.githubusercontent.com/{item['repository']}/{item['revision']}/{item['path']}"
        with urllib.request.urlopen(url, timeout=30) as response:
            data = response.read(item['size'] + 1)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    data = target.read_bytes()
    if len(data) != item['size'] or hashlib.sha256(data).hexdigest() != item['sha256']:
        raise ValueError('Pinned corpus integrity mismatch: ' + item['path'])
    return item, data


def signature_algorithm(kind, group):
    digest = group['sha']
    if kind == 'RSASSA-PSS':
        return seq(oid('1.2.840.113549.1.1.10') + seq(tlv('A0', alg(DIGESTS[digest]))
            + tlv('A1', seq(oid('1.2.840.113549.1.1.8') + alg(DIGESTS[group['mgfSha']])))
            + tlv('A2', integer(group['sLen']))))
    if kind == 'RSASSA-PKCS1-v1_5': return alg('1.2.840.113549.1.1.1')
    return seq(oid((EC_SIG if kind == 'ECDSA' else DSA_SIG)[digest]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--refresh-regressions', action='store_true',
                        help='Recreate the small tracked public-only regression subset from the pinned corpus')
    args = parser.parse_args()
    manifest = json.loads((ROOT/'Tests/ExternalCorpora/manifest.json').read_text())
    mapping = json.loads((ROOT/'Tests/ExternalCorpora/profile-mapping.json').read_text())
    signatures, agreements, macs, trust, images, exclusions = [], [], [], [], [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        sources = list(pool.map(fetch, manifest['sources']))
    for item, data in sources:
        if item['corpus'] == 'openjpeg':
            images.append({'id': Path(item['path']).name, 'data': data.hex()})
            continue
        source = json.loads(data)
        if item['corpus'] == 'limbo':
            for case in source['testcases']:
                category = case['id'].split('::')[0]
                reason = None
                if category not in ['rfc5280', 'pathlen', 'cve', 'invalid', 'crl']:
                    reason = 'web-PKI/online/other profile or separate pathological resource audit'
                elif case.get('max_chain_depth') is not None:
                    reason = 'application-specific configured chain-depth expectation'
                elif case['key_usage'] or case['extended_key_usage'] or 'wrong-san' in case['id'] or case['id'].startswith('rfc5280::san::'):
                    reason = 'TLS leaf-purpose or peer-name expectation'
                elif case.get('conflicts_with'):
                    reason = 'mutually incompatible validation profiles require separate mapping'
                if reason:
                    exclusions.append({'id': case['id'], 'reason': reason})
                    continue
                trust.append({'id': case['id'], 'description': case['description'], 'expected': case['expected_result'],
                    'roots': case['trusted_certs'], 'intermediates': case['untrusted_intermediates'],
                    'certificate': case['peer_certificate'], 'date': case['validation_time'], 'crls': case.get('crls', [])})
            continue
        kind = source['algorithm']
        for group in source['testGroups']:
            prefix = Path(item['path']).stem
            if kind in ['ECDSA', 'DSA', 'RSASSA-PSS', 'RSASSA-PKCS1-v1_5']:
                signatures.append({'id': prefix, 'key': group['publicKeyDer'], 'algorithm': signature_algorithm(kind, group).hex(),
                    'digest': group['sha'].lower().replace('-', ''), 'tests': [
                        {k: t[k] for k in ['tcId','msg','sig','result','flags']} for t in group['tests']]})
            elif kind == 'ECDH':
                tests=[]
                for t in group['tests']:
                    public = ec.derive_private_key(int(t['private'], 16), CURVES[group['curve']]()).public_key().public_bytes(
                        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
                    tests.append({**{k:t[k] for k in ['tcId','public','private','shared','result','flags']}, 'ownPublic':public.hex()})
                agreements.append({'id':prefix, 'curve': group['curve'], 'tests':tests})
            elif kind == 'AES-CMAC':
                macs.append({'id':prefix, 'tests':[{k:t[k] for k in ['tcId','key','msg','tag','result','flags']} for t in group['tests']]})
            else: raise ValueError('Unmapped vector type')
    OUT.mkdir(parents=True, exist_ok=True)
    for name, data in [('signatures',signatures),('agreements',agreements),('macs',macs),('trust',trust),('images',images)]:
        (OUT/f'{name}.json').write_text(json.dumps(data,separators=(',',':'))+'\n')
    (OUT/'profile-mapping.json').write_text(json.dumps(mapping,indent=2)+'\n')
    (CACHE/'excluded-limbo.json').write_text(json.dumps(exclusions,indent=2)+'\n')
    counts={'signatureVectors':sum(len(g['tests']) for g in signatures),'agreementVectors':sum(len(g['tests']) for g in agreements),
        'macVectors':sum(len(g['tests']) for g in macs),'trustCases':len(trust),'imageFiles':len(images),'excludedLimbo':len(exclusions)}
    (OUT/'counts.json').write_text(json.dumps(counts,indent=2)+'\n')
    if args.refresh_regressions:
        # Deliberate fixed case selection, not dynamically chosen by reader output.
        selected = {'secp256r1': [1, 359, 361], 'secp384r1': [1, 799, 801], 'secp521r1': [1, 660, 662]}
        keys = [{'id': f"{g['id']}/{t['tcId']}", 'public': t['public'], 'accepted': t['tcId'] != selected[g['curve']][2]}
                for g in agreements for t in g['tests'] if t['tcId'] in selected[g['curve']]]
        trust_ids = {'crl::structure::crl-empty', 'crl::structure::crl-duplicate-revoked-serial',
                     'rfc5280::root-and-intermediate-swapped', 'cve::cve-2024-0567',
                     'rfc5280::root-missing-basic-constraints', 'rfc5280::root-non-critical-basic-constraints',
                     'rfc5280::leaf-ku-keycertsign', 'rfc5280::aki::leaf-missing-aki',
                     'rfc5280::aki::intermediate-missing-aki', 'rfc5280::ski::root-missing-ski',
                     'rfc5280::ski::intermediate-missing-ski'}
        trust_subset = [t for t in trust if t['id'] in trust_ids or t['id'].startswith('rfc5280::validity::')]
        assert len(keys) == 9 and len(trust_subset) == 22
        regressions = {'provenance': 'Public synthetic cases from C2SP Wycheproof and x509-limbo; original DER/PEM bytes unchanged, private keys omitted. Apache-2.0; source revisions and SHA-256 in Tests/ExternalCorpora/manifest.json. See profile-mapping.json for the three omitted-cofactor cases.',
                       'publicKeys': keys, 'trust': trust_subset}
        (OUT.parent/'external-regressions.json').write_text(json.dumps(regressions,indent=2)+'\n')
    print(json.dumps(counts))

if __name__ == '__main__': main()
