# Master list generator

## What is it?
This script will create a file containing a set of unique CSCA (Country Signing Certificate Authority) certificates in PEM format from a country master List or the ICAO PKD repository.

These are used to verify both Document Signing certificates and Security Object DS Signatures (SOD) contained in e-passports and other electronic identity cards.

It can accept either the ICOA PDK master list file in LDIF format (which is a collection of master lists from validated countries), or a single Country masterlist file in Cryptographic Message Syntax (CMS) format.

# Where can I get a master list from?
ICAO makes their master lists available "freely available online to any person or State who wishes to download it. However, the process of downloading is manual and cannot be automated" (https://www.icao.int/Security/FAL/PKD/BVRT/Pages/Access.aspx) 

The master lists can be downloaded from: https://download.pkd.icao.int (previously was https://pkddownloadsg.icao.int but this seems to be unavailable now)

These are in LDIF (LDAP Data Interchange Format) format

Additionally, some countries make their master lists available (e.g. Germany, France and Italy are ones I've found). Do a search for <country> masterlist or the JMRTD project has a list (some links no longer work though) - https://jmrtd.org/certificates.shtml Yobi Wifi

These files will usually be zipped, so extract these files and you should end up with a <file>.ml.
 
 Obviously you should only use masterlists from a source you trust!

## Requirements

The script uses Python 3.7 (other versions of Python 3 may work - not tried).


It also requires a version of OpenSSL that supports the CMS flag.

The version that comes with macOS (including Catalina) doesn't support this so you will need to get that from somewhere else (e.g. Homebrew).

## Usage
To run the script, simply run:
python extract.py [Country master list.ml|ICAO LDIF file]

    e.g.
    python extract.py icaopkd-002-ml-000119.ldif


It will run through the masterlist(s) contained within the file and you should end up with a new masterList.pem file which is a concatenation of all the unique certificates.

This can then be imported into the NFCPassportReader app and used to verify an e-passport using Passive Authentication.

## Credits
This script is pretty much based on the details from http://wiki.yobi.be/wiki/EPassport with some additional bits for de-duplicating certificates. 

- `generate_diagnostic_fixtures.py`: creates the independent synthetic signed v0/v1 diagnostic corpus and test-only diagnostic CSCA. Requires Python cryptography; never saves private keys or modifies existing signed-passport fixtures. See `Tests/README.md`.
- `generate_sod_version_fixtures.py`: adds the signed SOD version/structure corpus and its own test-only CSCA. Preserves the original rc.5 signed v0/v1 fixtures and their root; requires Python cryptography and never saves private keys. See `Tests/README.md`.


## Synthetic standards fixtures

The `generate_*` scripts are test-only corpus generators, separate from trust-store extraction. New profiles cover SOD versions, CMS/PSS/signer binding, ISO/IEC 39794-5 faces, PACE explicit parameters, AA and offline CRLs. See [Tests/README.md](../Tests/README.md) for provenance and regeneration. They persist public parameters, synthetic certificates/CRLs, signed content and generated non-person images; private keys are generated in memory and never saved. Do not run them against real passport exports or replace the unchanged original v0/v1 acceptance fixtures. `generate_face_profiles.py` needs Pillow, signing generators need Python cryptography, and explicit EC/DH generation uses the installed OpenSSL CLI.

`release_check.sh` is the prescribed iOS regression gate. Its external API probe includes the optional local CRL configuration and revocation policy while continuing to require unsafe internal APIs to be inaccessible.

## Optional pinned external corpora

`python3 scripts/fetch_external_corpora.py` downloads and hash-verifies selected public Wycheproof, x509-limbo and OpenJPEG test inputs. It needs Python `cryptography`, executes no upstream code, uses ignored scratch/XCTest resource paths, and prints counts only. `--refresh-regressions` deliberately recreates the small tracked public-only subset; normal fetching leaves it untouched. See [corpus commands, mappings, provenance and limits](../Tests/ExternalCorpora/README.md). Run the prescribed release workflow after fetching for the full opt-in suite; six optional methods skip when absent, while three permanent corpus regressions always run.

`prepare_external_passports.py` fetches the [pinned whole-document samples](../Tests/ExternalPassports/README.md). Unlike the raw corpus fetcher, it deliberately runs four reviewed, hash-pinned Proxmark3 generator/helper files in a fresh temporary directory. It requires Pillow/cryptography, uses a pinned asn1crypto wheel, saves no private keys, uploads no data and retains generated documents only in ignored test resources. Counts/versions/outcomes are the only printed results. Published descriptions are not treated as standards-validity oracles.
