# ISO/IEC biometric schema attribution

The face decoder and synthetic fixture generator make use of the schemas from ISO/IEC 39794-1:2019 and ISO/IEC 39794-5:2019, with modifications permitted in the relevant standards and profiled by ICAO's August 2023 *ISO/IEC 39794-5 Application Profile for eMRTDs*, Annex A. Please reproduce this note if possible.

Source: https://www.icao.int/sites/default/files/TRIP/Publications/ICAO-TR-39794-5-eMRTD-Application-Profile.pdf

The schema's ISO/IEC copyright notice, conditions and disclaimer follow:

Use of ISO/IEC copyright in this Schema is licensed for the purpose of developing, implementing, and using software based on this Schema, subject to the following conditions:

* Software developed from this Schema must retain the Copyright Notice, this list of conditions and the disclaimer below ("Disclaimer").
* Neither the name or logo of ISO or of IEC, nor the names of specific contributors, may be used to endorse or promote software derived from this Schema without specific prior written permission.
* The software developer shall attribute the Schema to ISO/IEC and identify the ISO/IEC standard from which it is taken. Such attribution (e.g., "This software makes use of the Schema from ISO/IEC 39794-1 within modifications permitted in the relevant ISO/IEC standard. Please reproduce this note if possible."), may be placed in the software itself or any other reasonable location.

THE SCHEMA ON WHICH THIS SOFTWARE IS BASED IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE CODE COMPONENTS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Public cryptographic regression data

`Tests/NFCPassportReaderTests/Fixtures/external-regressions.json` contains a selected, field-reduced subset of public synthetic C2SP Wycheproof and x509-limbo vectors under Apache-2.0. The original public key/certificate/CRL bytes are unchanged; upstream private signing keys are not included. Source revisions, file hashes, exact case IDs, adaptations and profile differences are documented in [Tests/ExternalCorpora](Tests/ExternalCorpora/README.md). License texts: [Wycheproof](Tests/ExternalCorpora/WYCHEPROOF-LICENSE.txt), [x509-limbo](Tests/ExternalCorpora/LIMBO-LICENSE.txt). The optional larger corpora are fetched separately and ignored. OpenJPEG's selected malformed headers are not redistributed.

# External synthetic passport specimen

`Tests/NFCPassportReaderTests/Fixtures/external-passport-specimen.json` is an unchanged copy of `Sources/Resources/SamplePassport/emrtd-bundle.json` from [jeswr/pod-passport-scanner](https://github.com/jeswr/pod-passport-scanner), revision `d9c540b61f2ddad9ded26c48acfc600f68b5cadb`, © 2026 Jesse Wright, under the [included MIT license](Tests/ExternalPassports/SPECIMEN-LICENSE.txt). Its original signed bytes are preserved. Proxmark3 GPL source and generated samples are fetched/generated separately in ignored directories, not redistributed here. Source/version/hash and execution/coverage details are in [Tests/ExternalPassports](Tests/ExternalPassports/README.md).
