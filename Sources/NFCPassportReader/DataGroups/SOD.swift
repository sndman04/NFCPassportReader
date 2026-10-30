//
//  SOD.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation
import OpenSSL


// Format of SOD: ASN1 - Signed Data  (taken from rfc5652 - https://tools.ietf.org/html/rfc5652):
// The SOD is a CMS container of type Signed-data
//
// Sequence
//   Object ID: signedData
//   Content: SignedData
//       SignedData ::= SEQUENCE {
//           INTEGER version CMSVersion,
//           SET digestAlgorithms DigestAlgorithmIdentifiers,
//           SEQUENCE encapContentInfo EncapsulatedContentInfo,
//           certificates [0] IMPLICIT CertificateSet OPTIONAL,
//           crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//           SET signerInfos SignerInfos }
//
// AlgorithmIdentifier ::= SEQUENCE {
//     algorithm       OBJECT IDENTIFIER,
//     parameters      ANY OPTIONAL
// }
//
// EncapsulatedContentInfo ::= SEQUENCE {
//    eContentType ContentType,
//    eContent [0] EXPLICIT OCTET STRING OPTIONAL }
//
// ContentType ::= OBJECT IDENTIFIER
//
// SignerInfos ::= SET OF SignerInfo
//
// SignerInfo ::= SEQUENCE {
//     version CMSVersion,
//     sid SignerIdentifier,
//     digestAlgorithm DigestAlgorithmIdentifier,
//     signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//     signatureAlgorithm SignatureAlgorithmIdentifier,
//     signature SignatureValue,
//     unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
//
// SignerIdentifier ::= CHOICE {
//     issuerAndSerialNumber IssuerAndSerialNumber,
//     subjectKeyIdentifier [0] SubjectKeyIdentifier }
//
// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
// Attribute ::= SEQUENCE {
//     attrType OBJECT IDENTIFIER,
//     attrValues SET OF AttributeValue }
// AttributeValue ::= ANY
// SignatureValue ::= OCTET STRING
@available(iOS 13, macOS 10.15, *)
class SOD : DataGroup {
    
    public private(set) var pkcs7CertificateData : [UInt8] = []
    private var asn1Root : SimpleASN1Node?
    private var pubKey : OpaquePointer?

    private static let idSignedData = "1.2.840.113549.1.7.2"
    private static let idLdsSecurityObject = "2.23.136.1.1.1"
    private static let idMessageDigest = "1.2.840.113549.1.9.4"

    private static let digestAlgorithmNamesByOID: [String: String] = [
        "1.3.14.3.2.26": "SHA1",
        "2.16.840.1.101.3.4.2.4": "SHA224",
        "2.16.840.1.101.3.4.2.1": "SHA256",
        "2.16.840.1.101.3.4.2.2": "SHA384",
        "2.16.840.1.101.3.4.2.3": "SHA512"
    ]

    private static let signatureAlgorithmNamesByOID: [String: String] = [
        "1.2.840.10040.4.3": "dsa-with-sha1",
        "2.16.840.1.101.3.4.3.1": "dsa-with-sha224",
        "2.16.840.1.101.3.4.3.2": "dsa-with-sha256",
        "2.16.840.1.101.3.4.3.3": "dsa-with-sha384",
        "2.16.840.1.101.3.4.3.4": "dsa-with-sha512",
        "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
        "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10": "rsassaPss",
        "1.2.840.10045.4.1": "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1": "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4": "ecdsa-with-SHA512"
    ]

    override var datagroupType: DataGroupId { .SOD }
    
    required init( _ data : [UInt8] ) throws {
        try super.init(data)
        self.pkcs7CertificateData = body
    }
    
    deinit {
        clearPublicKey()
    }

    override func removeSensitiveDataForPrivacy() {
        pkcs7CertificateData.removeAll(keepingCapacity: false)
        asn1Root = nil
        clearPublicKey()
        super.removeSensitiveDataForPrivacy()
    }

    override func parse(_ data: [UInt8]) throws {
        asn1Root = try SimpleASN1Node.parse(body)
    }

    /// Metadata probing never changes verifier selection or acceptance.
    func captureDiagnosticMetadata(into evidence: inout PassportDiagnosticEvidence) {
        evidence.stages[.envelope] = .passed
        do {
            let signedData = try signedDataItem()
            evidence.stages[.signedData] = .passed
            evidence.contentDigest = PassportAlgorithmDiagnostic.read(
                signedData.children.dropFirst().first?.children.first, role: .digest)
        } catch {
            evidence.stages[.signedData] = .failed(.capture(error, stage: .passiveAuthentication, operation: .parseSOD))
        }
        do {
            let signer = try signerInfoItem()
            evidence.stages[.signerInfo] = .passed
            evidence.signerDigest = PassportAlgorithmDiagnostic.read(signer.children.dropFirst(2).first, role: .digest)
            evidence.signature = PassportAlgorithmDiagnostic.read(try signatureAlgorithmItem(in: signer), role: .signature)
        } catch {
            evidence.stages[.signerInfo] = .failed(.capture(error, stage: .passiveAuthentication, operation: .parseSOD))
        }
    }

    private func signedDataItem() throws -> SimpleASN1Node {
        guard let asn1Root,
              asn1Root.tag == 0x30,
              asn1Root.children.count == 2,
              let contentType = asn1Root.children.first,
              let explicitContent = asn1Root.children.dropFirst().first,
              contentType.objectIdentifier == Self.idSignedData,
              explicitContent.tag == 0xA0,
              explicitContent.children.count == 1,
              let signedData = explicitContent.children.first,
              signedData.tag == 0x30,
              (4...6).contains(signedData.children.count),
              signedData.children.first?.tag == 0x02,
              signedData.children.dropFirst().first?.tag == 0x31,
              signedData.children.dropFirst(2).first?.tag == 0x30,
              signedData.children.last?.tag == 0x31 else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        let optionalTags = signedData.children.dropFirst(3).dropLast().map(\.tag)
        guard optionalTags == [] || optionalTags == [0xA0] || optionalTags == [0xA1]
            || optionalTags == [0xA0, 0xA1] else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signedData
    }

    private func signerInfoItem(index: Int = 0) throws -> SimpleASN1Node {
        let signedData = try signedDataItem()
        guard let signerInfos = signedData.children.last,
              signerInfos.tag == 0x31,
              !signerInfos.children.isEmpty,
              signerInfos.children.allSatisfy({ $0.tag == 0x30 }),
              signerInfos.children.indices.contains(index) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signerInfos.children[index]
    }

    private func signedAttributesItem(in signerInfo: SimpleASN1Node) throws -> SimpleASN1Node {
        guard let signedAttributes = signerInfo.children.first(where: { $0.tag == 0xA0 }) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return signedAttributes
    }

    private func signatureAlgorithmItem(in signerInfo: SimpleASN1Node) throws -> SimpleASN1Node {
        if let signedAttributeIndex = signerInfo.children.firstIndex(where: { $0.tag == 0xA0 }),
           let item = signerInfo.children.dropFirst(signedAttributeIndex + 1).first {
            return item
        }

        guard let item = signerInfo.children.dropFirst(3).first else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return item
    }

    private func signatureItem(in signerInfo: SimpleASN1Node) throws -> SimpleASN1Node {
        if let signedAttributeIndex = signerInfo.children.firstIndex(where: { $0.tag == 0xA0 }),
           let item = signerInfo.children.dropFirst(signedAttributeIndex + 2).first {
            return item
        }

        guard let item = signerInfo.children.dropFirst(4).first else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        return item
    }
    
    /// Returns the public key from the embedded X509 certificate
    /// - Returns pointer to the public key
    func getPublicKey(signerIndex: Int = 0) throws -> OpaquePointer {
        
        clearPublicKey()
        let certs = try signingCertificates()
        guard certs.indices.contains(signerIndex) else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("No signing certificate found")
        }

        if let key = X509_get_pubkey(certs[signerIndex].cert) {
            pubKey = key
            return key
        }
        
        throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Unable to get public key")
    }

    func signingCertificates() throws -> [X509Wrapper] {
        try OpenSSLUtils.getCMSSignerCertificates(Data(body))
    }

    func validatedSignatureAlgorithms() throws -> [SODSignatureAlgorithm] {
        let signedData = try signedDataItem()
        guard signedData.children[0].value == [3],
              let signerSet = signedData.children.last, (1...16).contains(signerSet.children.count) else {
            throw SODSignatureAlgorithm.malformed()
        }
        let declaredDigests = try signedData.children[1].children.map { try SODSignatureAlgorithm.digest($0) }
        guard !declaredDigests.isEmpty else { throw SODSignatureAlgorithm.malformed() }
        return try signerSet.children.map { signer in
            guard signer.tag == 0x30, (6...7).contains(signer.children.count), signer.children[0].tag == 0x02,
                  signer.children[3].tag == 0xA0, signer.children[5].tag == 0x04,
                  !signer.children[5].value.isEmpty,
                  signer.children.count == 6 || signer.children[6].tag == 0xA1 else {
                throw SODSignatureAlgorithm.malformed()
            }
            let sid = signer.children[1]
            guard (sid.tag == 0x30 && signer.children[0].value == [1] && sid.children.count == 2
                   && sid.children[0].tag == 0x30 && sid.children[1].tag == 0x02 && !sid.children[1].value.isEmpty
                   && sid.children[1].value[0] & 0x80 == 0)
                || (sid.tag == 0x80 && signer.children[0].value == [3] && !sid.value.isEmpty) else {
                throw SODSignatureAlgorithm.malformed()
            }
            let digest = try SODSignatureAlgorithm.digest(signer.children[2])
            guard declaredDigests.contains(digest) else { throw SODSignatureAlgorithm.malformed() }
            let attrs = signer.children[3].children
            guard !attrs.isEmpty, attrs.allSatisfy({ $0.tag == 0x30 && $0.children.count == 2
                && $0.children[0].objectIdentifier != nil && $0.children[1].tag == 0x31
                && !$0.children[1].children.isEmpty }) else { throw SODSignatureAlgorithm.malformed() }
            let types = attrs.filter { $0.children[0].objectIdentifier == "1.2.840.113549.1.9.3" }
            let digests = attrs.filter { $0.children[0].objectIdentifier == Self.idMessageDigest }
            guard types.count == 1, types[0].children[1].children.count == 1,
                  types[0].children[1].children[0].objectIdentifier == Self.idLdsSecurityObject,
                  digests.count == 1, digests[0].children[1].children.count == 1,
                  digests[0].children[1].children[0].tag == 0x04 else { throw SODSignatureAlgorithm.malformed() }
            return try SODSignatureAlgorithm(signer.children[4], contentDigest: digest)
        }
    }

    private func clearPublicKey() {
        if let key = pubKey {
            EVP_PKEY_free(key)
            pubKey = nil
        }
    }
    
    
    /// Extracts the encapsulated content section from a SignedData PKCS7 container (if present)
    /// - Returns: The encapsulated content from a PKCS7 container if we could read it
    /// - Throws: Error if we can't find or read the encapsulated content
    func getEncapsulatedContent() throws -> Data {
        let signedData = try signedDataItem()
        guard let encapContentInfo = signedData.children.dropFirst(2).first,
              encapContentInfo.tag == 0x30,
              encapContentInfo.children.count == 2,
              encapContentInfo.children.first?.objectIdentifier == Self.idLdsSecurityObject,
              let eContent = encapContentInfo.children.dropFirst().first,
              eContent.tag == 0xA0,
              eContent.children.count == 1,
              let content = eContent.children.first,
              content.tag == 0x04 else {
            
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        return Data(content.value)
    }
    
    /// Gets the digest algorithm used to hash the encapsulated content in the signed data section (if present)
    /// - Returns: The digest algorithm used to hash the encapsulated content in the signed data section
    /// - Throws: Error if we can't find or read the digest algorithm
    func getEncapsulatedContentDigestAlgorithm(signerIndex: Int = 0, diagnostic: ((PassportDiagnosticReason) -> Void)? = nil) throws -> String {
        let signer = try signerInfoItem(index: signerIndex)
        guard signer.children.count >= 3 else { throw SODSignatureAlgorithm.malformed() }
        do { return try SODSignatureAlgorithm.digest(signer.children[2]).uppercased() }
        catch SODSignatureAlgorithm.Failure.unsupported {
            diagnostic?(.unsupportedAlgorithm)
            throw SODSignatureAlgorithm.unsupported()
        }
    }
    
    /// Gets the signed attributes section (if present)
    /// - Returns: the signed attributes section
    /// - Throws: Error if we can't find or read the signed attributes
    func getSignedAttributes(signerIndex: Int = 0) throws -> Data {
        let signerInfo = try signerInfoItem(index: signerIndex)
        let signedAttrs = try signedAttributesItem(in: signerInfo)
        
        var bytes = signedAttrs.encodedBytes
        guard !bytes.isEmpty else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        // The first byte will be 0xA0 -> as its a explicit tag for a contextual item which we need to convert
        // for the hash to calculate correctly
        // We know that the actual tag is a SET (0x31) - See section 5.4 of https://tools.ietf.org/html/rfc5652
        // So we need to change this from 0xA0 to 0x31
        if bytes[0] == 0xA0 {
            bytes[0] = 0x31
        }
        let signedAttribs = Data(bytes)
        
        return signedAttribs
    }
    
/// Gets the message digest from the signed attributes section (if present)
/// - Returns: the message digest
/// - Throws: Error if we can't find or read the message digest
    func getMessageDigestFromSignedAttributes(signerIndex: Int = 0) throws -> Data {
        
        // For the SOD, the SignedAttributes consists of:
        // A Content type Object (which has the value of the attributes content type)
        // A messageDigest Object which has the message digest as it value
        // We want the messageDigest value
        
        let signerInfo = try signerInfoItem(index: signerIndex)
        let signedAttrs = try signedAttributesItem(in: signerInfo)
        
        let messageDigestAttributes = signedAttrs.children.filter {
            $0.tag == 0x30 && $0.children.first?.objectIdentifier == Self.idMessageDigest
        }
        guard messageDigestAttributes.count == 1,
              let messageDigestAttribute = messageDigestAttributes.first,
              messageDigestAttribute.children.count == 2,
              let attrValues = messageDigestAttribute.children.dropFirst().first,
              attrValues.tag == 0x31,
              attrValues.children.count == 1,
              let digestVal = attrValues.children.first,
              digestVal.tag == 0x04 else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("No messageDigest Returned")
        }
        
        let messageDigest = Data(digestVal.value)
        
        return messageDigest
    }
    
    /// Gets the signature data (if present)
    /// - Returns: the signature
    /// - Throws: Error if we can't find or read the signature
    func getSignature(signerIndex: Int = 0) throws -> Data {
        let signerInfo = try signerInfoItem(index: signerIndex)
        let signature = try signatureItem(in: signerInfo)
        
        guard signature.tag == 0x04 else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }

        return Data(signature.value)
    }
    
    /// Gets the signature algorithm used (if present)
    /// - Returns: the signature algorithm used
    /// - Throws: Error if we can't find or read the signature algorithm
    func getSignatureAlgorithm(signerIndex: Int = 0, diagnostic: ((PassportDiagnosticReason) -> Void)? = nil) throws -> String {
        let signerInfo = try signerInfoItem(index: signerIndex)
        let signatureAlgorithm = try signatureAlgorithmItem(in: signerInfo)
        guard let signatureAlgorithmOID = signatureAlgorithm.children.first?.objectIdentifier else {
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        
        guard let signatureAlgorithmName = Self.signatureAlgorithmNamesByOID[signatureAlgorithmOID] else {
            diagnostic?(.unsupportedAlgorithm)
            throw OpenSSLError.UnableToExtractSignedDataFromPKCS7("Data in invalid format")
        }
        // Vals I've seen are:
        // sha1WithRSAEncryption => default pkcs1
        // sha256WithRSAEncryption => default pkcs1
        // rsassaPss => pss        
        return signatureAlgorithmName
    }
}
