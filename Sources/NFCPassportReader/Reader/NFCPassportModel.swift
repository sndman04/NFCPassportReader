//
//  NFCPassportModel.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 29/10/2019.
//


import Foundation

#if os(iOS)
import UIKit
#endif


enum PassportAuthenticationStatus {
    case notDone
    case success
    case failed
}

@available(iOS 13, macOS 10.15, *)
// Legacy mutable result type returned by the async reader API. PassportReader transfers it to
// the caller at completion and releases its own sensitive scan references immediately afterward.
class NFCPassportModel: @unchecked Sendable {
    private static let activeAuthenticationChallengeLength = 8
    private static let maxActiveAuthenticationSignatureLength = 64 * 1024

    private struct ProjectedName {
        let lastName: String
        let firstName: String
    }
    
    public var documentType : String { return String( passportDataElements?["5F03"]?.first ?? "?" ) }
    public var documentSubType : String { return String( passportDataElements?["5F03"]?.last ?? "?" ) }
    public var documentNumber : String { return (passportDataElements?["5A"] ?? "?").replacingOccurrences(of: "<", with: "" ) }
    public var issuingAuthority : String { return passportDataElements?["5F28"] ?? "?" }
    public var documentExpiryDate : String { return passportDataElements?["59"] ?? "?" }
    public var dateOfIssue : String? {
        guard let dg12 = dataGroupsRead[.DG12] as? DataGroup12 else { return nil }
        return dg12.dateOfIssue
    }
    public var dateOfBirth : String { return passportDataElements?["5F57"] ?? "?" }
    public var gender : String { return passportDataElements?["5F35"] ?? "?" }
    public var nationality : String { return passportDataElements?["5F2C"] ?? "?" }
    
    public var lastName : String {
        return projectedName.lastName
    }
    
    public var firstName : String {
        return projectedName.firstName
    }
    
    // DG11 can carry a fuller name, but it is optional and issuer-specific. Prefer it only
    // when it has a parseable ICAO-style separator; otherwise fall back to validated DG1 MRZ.
    private var projectedName : ProjectedName {
        if let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
           let dg11Name = Self.projectedName(from: dg11.fullName, requiresPrimarySeparator: true) {
            return dg11Name
        }

        return Self.projectedName(from: passportDataElements?["5B"], requiresPrimarySeparator: false) ??
            ProjectedName(lastName: "?", firstName: "")
    }
    
    public var placeOfBirth : String? {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let placeOfBirth = dg11.placeOfBirth else { return nil }
        return Self.normalizedOptionalTextValue(placeOfBirth)
    }
    
    /// residence address
    public var residenceAddress : String? {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let address = dg11.address else { return nil }
        return Self.normalizedOptionalTextValue(address)
    }
    
    /// phone number
    public var phoneNumber : String? {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let telephone = dg11.telephone else { return nil }
        return Self.normalizedOptionalTextValue(telephone)
    }
    
    /// personal number
    public var personalNumber : String? {
        if let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
           let personalNumber = Self.normalizedOptionalIdentityValue(dg11.personalNumber) {
            return personalNumber
        }

        return Self.normalizedOptionalIdentityValue(passportDataElements?["53"])
    }
    
    /// face image info
    public var faceImageInfo : FaceImageInfo? {
        guard let dg2 = dataGroupsRead[.DG2] as? DataGroup2 else { return nil }
        
        return FaceImageInfo.from(dg2: dg2)
    }

    var documentSigningCertificate : X509Wrapper? {
        return certificateSigningGroups[.documentSigningCertificate]
    }

    var countrySigningCertificate : X509Wrapper? {
        return certificateSigningGroups[.issuerSigningCertificate]
    }
    
    // Extract data from COM
    public var LDSVersion : String {
        guard let com = dataGroupsRead[.COM] as? COM else { return "Unknown" }
        return com.version
    }
    
    
    public var dataGroupsPresent : [String] {
        guard let com = dataGroupsRead[.COM] as? COM else { return [] }
        return com.dataGroupsPresent
    }
    
    // Parsed datagroup hashes
    public private(set) var dataGroupsAvailable = [DataGroupId]()
    /// Raw parsed data groups retained internally for verification and safe result projection.
    public private(set) var dataGroupsRead : [DataGroupId:DataGroup] = [:]
    public private(set) var dataGroupHashes = [DataGroupId: DataGroupHash]()
    public private(set) var dataGroupReadReports: [PassportDataGroupReadReport] = []
    private var sodHashDataGroupIds = Set<DataGroupId>()

    public internal(set) var cardAccess : CardAccess?
    internal var cardSecurity: CardSecurity?
    internal var paceChipAuthenticationMappingResult: PACEChipAuthenticationMappingResult?
    public internal(set) var BACStatus : PassportAuthenticationStatus = .notDone
    public internal(set) var PACEStatus : PassportAuthenticationStatus = .notDone
    public internal(set) var chipAuthenticationStatus : PassportAuthenticationStatus = .notDone

    public private(set) var passportCorrectlySigned : Bool = false
    public private(set) var documentSigningCertificateVerified : Bool = false
    public private(set) var passportDataNotTampered : Bool = false
    public private(set) var activeAuthenticationPassed : Bool = false
    public private(set) var activeAuthenticationAttempted : Bool = false
    /// Sensitive Active Authentication challenge retained internally until safe result projection completes.
    public private(set) var activeAuthenticationChallenge : [UInt8] = []
    /// Sensitive Active Authentication signature retained internally until safe result projection completes.
    public private(set) var activeAuthenticationSignature : [UInt8] = []
    public private(set) var verificationErrors : [Error] = []
    public private(set) var passportVerificationAttempted : Bool = false
    public private(set) var masterListWasProvided : Bool = false
    public private(set) var masterListModifiedDate : Date?
    public private(set) var revocationCheckPerformed : Bool = false

    var verificationResult: PassportVerificationResult {
        let sodSignatureDetail = verificationCheckForSODSignature()
        let dataGroupHashDetail = verificationCheckForDataGroupHashes()
        let documentSignerCertificateDetail = verificationCheckForDocumentSignerCertificate()
        let countrySigningCertificateDetail = verificationCheckForCountrySigningCertificate()
        let activeAuthenticationDetail = verificationCheckForActiveAuthentication()
        let chipAuthenticationDetail = verificationCheckForChipAuthentication()

        return PassportVerificationResult(
            sodSignatureStatus: sodSignatureDetail.status,
            dataGroupHashStatus: dataGroupHashDetail.status,
            documentSignerCertificateStatus: documentSignerCertificateDetail.status,
            countrySigningCertificateStatus: countrySigningCertificateDetail.status,
            activeAuthenticationStatus: activeAuthenticationDetail.status,
            chipAuthenticationStatus: chipAuthenticationDetail.status,
            sodSignatureDetail: sodSignatureDetail,
            dataGroupHashDetail: dataGroupHashDetail,
            documentSignerCertificateDetail: documentSignerCertificateDetail,
            countrySigningCertificateDetail: countrySigningCertificateDetail,
            activeAuthenticationDetail: activeAuthenticationDetail,
            chipAuthenticationDetail: chipAuthenticationDetail,
            dataGroupCoverage: dataGroupVerificationCoverage()
        )
    }

    var isPACESupported : Bool {
        get {
            if cardAccess?.paceInfo != nil {
                return true
            } else {
                // We may not have stored the cardAccess so check the DG14
                if let dg14 = dataGroupsRead[.DG14] as? DataGroup14,
                   (dg14.securityInfos.filter { ($0 as? PACEInfo) != nil }).count > 0 {
                    return true
                }
                return false
            }
        }
    }
    
    var isChipAuthenticationSupported : Bool {
        get {
            if let dg14 = dataGroupsRead[.DG14] as? DataGroup14,
               (dg14.securityInfos.filter { ($0 as? ChipAuthenticationPublicKeyInfo) != nil }).count > 0 {
                
                return true
            } else {
                return false
            }
        }
    }
    
#if os(iOS)
    var passportImage : UIImage? {
        guard let dg2 = dataGroupsRead[.DG2] as? DataGroup2 else { return nil }
        
        return dg2.getImage()
    }

    var signatureImage : UIImage? {
        guard let dg7 = dataGroupsRead[.DG7] as? DataGroup7 else { return nil }
        
        return dg7.getImage()
    }
#endif

    var activeAuthenticationSupported : Bool {
        guard let dg15 = dataGroupsRead[.DG15] as? DataGroup15 else { return false }
        if dg15.ecdsaPublicKey != nil || dg15.rsaPublicKey != nil {
            return true
        }
        return false
    }

    private var certificateSigningGroups : [CertificateType:X509Wrapper] = [:]

    private var passportDataElements : [String:String]? {
        guard let dg1 = dataGroupsRead[.DG1] as? DataGroup1 else { return nil }
        
        return dg1.elements
    }

    private static func projectedName(from value: String?, requiresPrimarySeparator: Bool) -> ProjectedName? {
        guard let value = value else { return nil }
        let trimmedValue = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedValue.isEmpty else { return nil }
        guard !requiresPrimarySeparator || trimmedValue.contains("<<") else { return nil }

        let components = trimmedValue.components(separatedBy: "<<")
        guard let primaryComponent = components.first,
              let lastName = normalizedNameComponent(primaryComponent),
              !lastName.isEmpty else {
            return nil
        }

        let firstName = components.dropFirst()
            .compactMap { normalizedNameComponent($0) }
            .joined(separator: " ")
        return ProjectedName(lastName: lastName, firstName: firstName)
    }

    private static func normalizedNameComponent(_ value: String) -> String? {
        let words = value
            .replacingOccurrences(of: "<", with: " ")
            .components(separatedBy: .whitespacesAndNewlines)
            .filter { !$0.isEmpty }

        guard !words.isEmpty else { return nil }
        return words.joined(separator: " ")
    }

    private static func normalizedOptionalIdentityValue(_ value: String?) -> String? {
        guard let value = value else { return nil }
        let normalized = value
            .replacingOccurrences(of: "<", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return normalized.isEmpty ? nil : normalized
    }

    private static func normalizedOptionalTextValue(_ value: String?) -> String? {
        guard let value = value else { return nil }
        let normalized = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else { return nil }
        guard normalized.contains(where: { $0 != "<" }) else { return nil }
        return normalized
    }
        
    
    public init() {
        
    }
    
    func addDataGroup(_ id : DataGroupId, dataGroup: DataGroup ) {
        resetPassiveVerificationStateForDataMutation()
        if id == .DG14 || id == .DG15 {
            resetActiveAuthenticationStateForDataMutation()
        }
        if id == .DG14 {
            chipAuthenticationStatus = .notDone
        }

        if let existingDataGroup = self.dataGroupsRead[id],
           existingDataGroup !== dataGroup {
            existingDataGroup.removeSensitiveDataForPrivacy()
        }
        self.dataGroupsRead[id] = dataGroup
        if id != .COM && id != .SOD && !self.dataGroupsAvailable.contains(id) {
            self.dataGroupsAvailable.append( id )
        }
    }

    func getDataGroup( _ id : DataGroupId ) -> DataGroup? {
        return dataGroupsRead[id]
    }

    /// Best-effort cleanup for sensitive raw chip material retained by the internal working model.
    ///
    /// Call this after projecting the values needed by the host app. This clears parsed raw data groups,
    /// hashes, card-access data, certificate objects, and active-authentication material held by this
    /// model instance. Swift value copies and framework internals may still retain their own memory, so
    /// this is data minimization rather than a complete zeroization guarantee.
    func removeSensitiveDataForPrivacy() {
        dataGroupsAvailable.removeAll(keepingCapacity: false)
        dataGroupsRead.values.forEach { $0.removeSensitiveDataForPrivacy() }
        dataGroupsRead.removeAll(keepingCapacity: false)
        dataGroupHashes.removeAll(keepingCapacity: false)
        sodHashDataGroupIds.removeAll(keepingCapacity: false)
        dataGroupReadReports.removeAll(keepingCapacity: false)
        cardAccess?.removeSensitiveDataForPrivacy()
        cardAccess = nil
        cardSecurity?.removeSensitiveDataForPrivacy()
        cardSecurity = nil
        paceChipAuthenticationMappingResult = nil
        certificateSigningGroups.removeAll(keepingCapacity: false)
        BACStatus = .notDone
        PACEStatus = .notDone
        chipAuthenticationStatus = .notDone
        passportCorrectlySigned = false
        documentSigningCertificateVerified = false
        passportDataNotTampered = false
        verificationErrors.removeAll(keepingCapacity: false)
        passportVerificationAttempted = false
        masterListWasProvided = false
        masterListModifiedDate = nil
        revocationCheckPerformed = false
        activeAuthenticationPassed = false
        activeAuthenticationAttempted = false
        activeAuthenticationChallenge.removeAll(keepingCapacity: false)
        activeAuthenticationSignature.removeAll(keepingCapacity: false)
    }

    private func resetPassiveVerificationStateForDataMutation() {
        passportVerificationAttempted = false
        masterListWasProvided = false
        masterListModifiedDate = nil
        revocationCheckPerformed = false
        passportCorrectlySigned = false
        documentSigningCertificateVerified = false
        passportDataNotTampered = false
        verificationErrors.removeAll(keepingCapacity: false)
        dataGroupHashes.removeAll(keepingCapacity: false)
        sodHashDataGroupIds.removeAll(keepingCapacity: false)
        certificateSigningGroups.removeAll(keepingCapacity: false)
    }

    private func resetActiveAuthenticationStateForDataMutation() {
        activeAuthenticationPassed = false
        activeAuthenticationAttempted = false
        activeAuthenticationChallenge.removeAll(keepingCapacity: false)
        activeAuthenticationSignature.removeAll(keepingCapacity: false)
    }

    func recordDataGroupReadStatus(_ status: PassportDataGroupReadStatus, for id: DataGroupId) {
        guard id != .Unknown else { return }
        dataGroupReadReports.removeAll { report in
            report.dataGroup == id && status.replaces(report.status)
        }
        let report = PassportDataGroupReadReport(dataGroup: id, status: status)
        if !dataGroupReadReports.contains(report) {
            dataGroupReadReports.append(report)
        }
    }

    func getHashesForDatagroups( hashAlgorythm: String ) -> [DataGroupId:[UInt8]]  {
        var ret = [DataGroupId:[UInt8]]()
        
        for (key, value) in dataGroupsRead {
            let hash = value.hash(hashAlgorythm)
            if !hash.isEmpty {
                ret[key] = hash
            }
        }
        
        return ret
    }
    
            
    /// This method performs the passive authentication
    /// Passive Authentication : Two Parts:
    /// Part 1 - Has the SOD (Security Object Document) been signed by a valid country signing certificate authority (CSCA)?
    /// Part 2 - has it been tampered with (e.g. hashes of Datagroups match those in the SOD?
    ///        guard let sod = model.getDataGroup(.SOD) else { return }
    ///
    /// - Parameter masterListURL: the path to the masterlist to try to verify the document signing certiifcate in the SOD
    /// - Parameter useCMSVerification: Should we use OpenSSL CMS verification to verify the SOD content
    ///         is correctly signed by the document signing certificate OR should we do this manully based on RFC5652
    ///         CMS fails under certain circumstances (e.g. hashes are SHA512 whereas content is signed with SHA256RSA).
    ///         Currently defaulting to manual verification - hoping this will replace the CMS verification totally
    ///         CMS Verification currently there just in case
    func verifyPassport( masterListURL: URL?, useCMSVerification : Bool = false ) {
        passportVerificationAttempted = true
        masterListWasProvided = masterListURL != nil
        masterListModifiedDate = masterListURL?.privacySafeFileModificationDate
        revocationCheckPerformed = false
        verificationErrors = []
        passportCorrectlySigned = false
        documentSigningCertificateVerified = false
        passportDataNotTampered = false
        dataGroupHashes = [:]
        sodHashDataGroupIds.removeAll(keepingCapacity: false)
        certificateSigningGroups = [:]

        if let masterListURL = masterListURL {
            do {
                try validateAndExtractSigningCertificates( masterListURL: masterListURL )
            } catch let error {
                verificationErrors.append( error )
            }
        }
        
        do {
            try ensureReadDataNotBeenTamperedWith( useCMSVerification : useCMSVerification )
        } catch let error {
            verificationErrors.append( error )
        }
    }
    
    func verifyActiveAuthentication( challenge: [UInt8], signature: [UInt8] ) {
        // Get AA Public key
        self.activeAuthenticationAttempted = true
        self.activeAuthenticationPassed = false
        self.activeAuthenticationChallenge.removeAll(keepingCapacity: false)
        self.activeAuthenticationSignature.removeAll(keepingCapacity: false)

        guard Self.isValidActiveAuthenticationInput(challenge: challenge, signature: signature) else {
            return
        }

        self.activeAuthenticationChallenge = challenge
        self.activeAuthenticationSignature = signature

        guard  let dg15 = self.dataGroupsRead[.DG15] as? DataGroup15 else { return }
        if let rsaKey = dg15.rsaPublicKey {
            do {
                var decryptedSig = try OpenSSLUtils.decryptRSASignature(signature: Data(signature), pubKey: rsaKey)
                
                // Decrypted signature compromises of header (6A), Message, Digest hash, Trailer
                // Trailer can be 1 byte (BC - SHA-1 hash) or 2 bytes (xxCC) - where xx identifies the hash algorithm used
                
                // If the last byte is 0xBC, this uses dedicated hash function 3 (SHA-1).
                // If the last byte is 0xCC, the preceding byte identifies the hash function.
                // See ISO/IEC9796-2 for details on the verification and ISO/IEC 10118-3 for the dedicated hash functions!
                var hashTypeByte = decryptedSig.popLast() ?? 0x00
                if hashTypeByte == 0xCC {
                    hashTypeByte = decryptedSig.popLast() ?? 0x00
                }
                var hashType : String = ""
                var hashLength = 0

                switch hashTypeByte {
                    case 0xBC, 0x33:
                        hashType = "SHA1"
                        hashLength = 20  // 160 bits for SHA-1 -> 20 bytes
                    case 0x34:
                        hashType = "SHA256"
                        hashLength = 32  // 256 bits for SHA-256 -> 32 bytes
                    case 0x35:
                        hashType = "SHA512"
                        hashLength = 64  // 512 bits for SHA-512 -> 64 bytes
                    case 0x36:
                        hashType = "SHA384"
                        hashLength = 48  // 384 bits for SHA-384 -> 48 bytes
                    case 0x38:
                        hashType = "SHA224"
                        hashLength = 28  // 224 bits for SHA-224 -> 28 bytes
                    default:
                        return
                }
                
                guard decryptedSig.count > hashLength + 1 else {
                    return
                }

                let message = [UInt8](decryptedSig[1 ..< (decryptedSig.count-hashLength)])
                let digest = [UInt8](decryptedSig[(decryptedSig.count-hashLength)...])

                // Concatenate the challenge to the end of the message
                let fullMsg = message + challenge
                
                // Then generate the hash
                let msgHash : [UInt8] = try calcHash(data: fullMsg, hashAlgorithm: hashType)
                
                // Check hashes match
                if msgHash == digest {
                    self.activeAuthenticationPassed = true
                } else {
                }
            } catch {
            }
        } else if let ecdsaPublicKey = dg15.ecdsaPublicKey {
            var digestType = ""
            if let dg14 = dataGroupsRead[.DG14] as? DataGroup14,
               let aa = dg14.securityInfos.compactMap({ $0 as? ActiveAuthenticationInfo }).first {
                digestType = aa.getSignatureAlgorithmOIDString() ?? ""
            }
            
            if OpenSSLUtils.verifyECDSASignature( publicKey:ecdsaPublicKey, signature: signature, data: challenge, digestType: digestType ) {
                self.activeAuthenticationPassed = true
            } else {
            }
        }
    }

    nonisolated static func isValidActiveAuthenticationInput(challenge: [UInt8], signature: [UInt8]) -> Bool {
        isValidActiveAuthenticationChallenge(challenge)
            && !signature.isEmpty
            && signature.count <= maxActiveAuthenticationSignatureLength
    }

    nonisolated static func isValidActiveAuthenticationChallenge(_ challenge: [UInt8]) -> Bool {
        challenge.count == activeAuthenticationChallengeLength
    }
    
    private func validateAndExtractSigningCertificates( masterListURL: URL ) throws {
        self.passportCorrectlySigned = false
        
        guard let sod = getDataGroup(.SOD) else {
            throw PassiveAuthenticationError.SODMissing("No SOD found" )
        }

        let data = Data(sod.body)
        guard let cert = try OpenSSLUtils.getX509CertificatesFromPKCS7( pkcs7Der: data ).first else {
            throw OpenSSLError.UnableToGetX509CertificateFromPKCS7("No signing certificate found")
        }
        self.certificateSigningGroups[.documentSigningCertificate] = cert

        let rc = OpenSSLUtils.verifyTrustAndGetIssuerCertificate( x509:cert, CAFile: masterListURL )
        switch rc {
        case .success(let csca):
            self.certificateSigningGroups[.issuerSigningCertificate] = csca
        case .failure(let error):
            throw error
        }
        self.passportCorrectlySigned = true

    }

    private func ensureReadDataNotBeenTamperedWith( useCMSVerification: Bool ) throws  {
        guard let sod = getDataGroup(.SOD) as? SOD else {
            throw PassiveAuthenticationError.SODMissing("No SOD found" )
        }

        // Get SOD Content and verify that its correctly signed by the Document Signing Certificate
        var signedData : Data
        documentSigningCertificateVerified = false
        do {
            signedData = try verifySODAndReturnEncapsulatedContent(sod: sod, preferCMSVerification: useCMSVerification)
            documentSigningCertificateVerified = true
        } catch let signatureVerificationError {
            verificationErrors.append(signatureVerificationError)
            signedData = try sod.getEncapsulatedContent()
        }
                
        // Now Verify passport data by comparing compare Hashes in SOD against
        // computed hashes to ensure data not been tampered with
        passportDataNotTampered = false
        let (sodHashAlgorythm, sodHashes) = try parseSODSignatureContent(data: signedData)
        sodHashDataGroupIds = Set(sodHashes.keys)
        
        var errorSummaries: [String] = []
        var comparedDataGroupCount = 0
        for (id,dgVal) in dataGroupsRead {
            guard let sodHashVal = sodHashes[id] else {
                // SOD and COM don't have hashes so these aren't errors
                if id != .SOD && id != .COM {
                    errorSummaries.append("\(id.getName()) missing from SOD hashes")
                }
                continue
            }
            
            let computedHashVal = binToHexRep(dgVal.hash(sodHashAlgorythm))
            
            var match = true
            if computedHashVal != sodHashVal {
                errorSummaries.append("\(id.getName()) hash mismatch")
                match = false
            }

            dataGroupHashes[id] = DataGroupHash(id: id.getName(), sodHash:sodHashVal, computedHash:computedHashVal, match:match)
            comparedDataGroupCount += 1
        }
        
        if !errorSummaries.isEmpty {
            throw PassiveAuthenticationError.InvalidDataGroupHash(errorSummaries.joined(separator: "; "))
        }
        guard comparedDataGroupCount > 0 else {
            throw PassiveAuthenticationError.NoDataGroupHashesCompared("No read data groups were present in SOD hashes")
        }
        passportDataNotTampered = true
    }

    private func verifySODAndReturnEncapsulatedContent(sod: SOD, preferCMSVerification: Bool) throws -> Data {
        if preferCMSVerification {
            do {
                return try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod)
            } catch {
                return try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod)
            }
        } else {
            do {
                return try OpenSSLUtils.verifyAndReturnSODEncapsulatedData(sod: sod)
            } catch {
                return try OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS(sod: sod)
            }
        }
    }
    
    
    /// Parses the structured LDS Security Object and extracts the digest algorithm and data-group hashes.
    /// - Parameter data: DER-encoded LDS Security Object content.
    /// - Returns: The digest algorithm and a dictionary of hashes for SOD-listed data groups.
    func parseSODSignatureContent(data: Data) throws -> (String, [DataGroupId : String]) {
        let root = try SimpleASN1Node.parse([UInt8](data))
        guard root.tag == 0x30,
              let version = root.children.first,
              version.tag == 0x02,
              version.integerValue == 0,
              let digestAlgorithmInfo = root.children.dropFirst().first,
              digestAlgorithmInfo.tag == 0x30,
              let digestAlgorithmOID = digestAlgorithmInfo.children.first?.objectIdentifier,
              let digestAlgorithm = hashAlgorithmName(for: digestAlgorithmOID) else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to parse structured SOD hashes")
        }

        guard let dataGroupHashValues = root.children.dropFirst(2).first,
              dataGroupHashValues.tag == 0x30 else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to parse structured SOD hashes")
        }

        guard let expectedHashLength = hashLength(for: digestAlgorithm) else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unsupported hash algorithm")
        }

        var sodHashes: [DataGroupId: String] = [:]
        for hashValue in dataGroupHashValues.children {
            guard hashValue.tag == 0x30,
                  hashValue.children.count == 2,
                  let dataGroupNumberNode = hashValue.children.first,
                  let hashNode = hashValue.children.dropFirst().first,
                  let dataGroupNumber = dataGroupNumberNode.integerValue,
                  let dataGroupId = dataGroupId(forSODNumber: dataGroupNumber),
                  hashNode.tag == 0x04 else {
                throw PassiveAuthenticationError.UnableToParseSODHashes("Invalid data group hash structure")
            }
            guard hashNode.value.count == expectedHashLength else {
                throw PassiveAuthenticationError.UnableToParseSODHashes("Invalid data group hash length")
            }
            guard sodHashes[dataGroupId] == nil else {
                throw PassiveAuthenticationError.UnableToParseSODHashes("Duplicate data group hash")
            }

            sodHashes[dataGroupId] = binToHexRep(hashNode.value)
        }

        guard !sodHashes.isEmpty else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to extract hashes")
        }

        return (digestAlgorithm, sodHashes)
    }

    private func hashLength(for algorithm: String) -> Int? {
        switch algorithm {
        case "SHA1": return 20
        case "SHA224": return 28
        case "SHA256": return 32
        case "SHA384": return 48
        case "SHA512": return 64
        default: return nil
        }
    }

    private func hashAlgorithmName(for oid: String) -> String? {
        switch oid {
        case "1.3.14.3.2.26":
            return "SHA1"
        case "2.16.840.1.101.3.4.2.4":
            return "SHA224"
        case "2.16.840.1.101.3.4.2.1":
            return "SHA256"
        case "2.16.840.1.101.3.4.2.2":
            return "SHA384"
        case "2.16.840.1.101.3.4.2.3":
            return "SHA512"
        default:
            return nil
        }
    }

    private func dataGroupId(forSODNumber number: Int) -> DataGroupId? {
        switch number {
        case 1: return .DG1
        case 2: return .DG2
        case 3: return .DG3
        case 4: return .DG4
        case 5: return .DG5
        case 6: return .DG6
        case 7: return .DG7
        case 8: return .DG8
        case 9: return .DG9
        case 10: return .DG10
        case 11: return .DG11
        case 12: return .DG12
        case 13: return .DG13
        case 14: return .DG14
        case 15: return .DG15
        case 16: return .DG16
        default: return nil
        }
    }

    private func verificationCheckForSODSignature() -> PassportVerificationCheck {
        guard passportVerificationAttempted else {
            return PassportVerificationCheck(status: .notChecked, reason: .notRequested)
        }
        guard getDataGroup(.SOD) != nil else {
            return PassportVerificationCheck(status: .failed, reason: .missingSOD)
        }
        if documentSigningCertificateVerified {
            return PassportVerificationCheck(status: .passed, reason: .passed)
        }
        if verificationErrors.contains(where: { $0 is OpenSSLError }) {
            return PassportVerificationCheck(status: .failed, reason: .signatureInvalid)
        }
        return PassportVerificationCheck(status: .failed, reason: .attemptedFailed)
    }

    private func verificationCheckForDataGroupHashes() -> PassportVerificationCheck {
        guard passportVerificationAttempted else {
            return PassportVerificationCheck(status: .notChecked, reason: .notRequested)
        }
        guard getDataGroup(.SOD) != nil else {
            return PassportVerificationCheck(status: .failed, reason: .missingSOD)
        }
        if passportDataNotTampered {
            return PassportVerificationCheck(status: .passed, reason: .passed)
        }
        if verificationErrors.contains(where: { error in
            if case PassiveAuthenticationError.InvalidDataGroupHash = error { return true }
            return false
        }) {
            return PassportVerificationCheck(status: .failed, reason: .hashMismatch)
        }
        if verificationErrors.contains(where: { error in
            if case PassiveAuthenticationError.UnableToParseSODHashes = error { return true }
            return false
        }) {
            return PassportVerificationCheck(status: .failed, reason: .malformedSOD)
        }
        if verificationErrors.contains(where: { $0 is NFCPassportReaderError }) {
            return PassportVerificationCheck(status: .failed, reason: .unsupportedAlgorithm)
        }
        return PassportVerificationCheck(status: .failed, reason: .attemptedFailed)
    }

    private func verificationCheckForDocumentSignerCertificate() -> PassportVerificationCheck {
        guard passportVerificationAttempted else {
            return PassportVerificationCheck(status: .notChecked, reason: .notRequested)
        }
        guard getDataGroup(.SOD) != nil else {
            return PassportVerificationCheck(status: .failed, reason: .missingSOD)
        }
        return documentSigningCertificateVerified
            ? PassportVerificationCheck(status: .passed, reason: .passed)
            : PassportVerificationCheck(status: .failed, reason: .signatureInvalid)
    }

    private func verificationCheckForCountrySigningCertificate() -> PassportVerificationCheck {
        guard passportVerificationAttempted else {
            return PassportVerificationCheck(status: .notChecked, reason: .notRequested)
        }
        guard masterListWasProvided else {
            return PassportVerificationCheck(status: .notChecked, reason: .missingMasterList)
        }
        return passportCorrectlySigned
            ? PassportVerificationCheck(status: .passed, reason: .passed)
            : PassportVerificationCheck(status: .failed, reason: .signerUntrusted)
    }

    private func verificationCheckForActiveAuthentication() -> PassportVerificationCheck {
        guard activeAuthenticationSupported else {
            let dg15Statuses = dataGroupReadReports
                .filter { $0.dataGroup == .DG15 }
                .map(\.status)

            if dg15Statuses.contains(.skippedByProfile) || dg15Statuses.contains(.blockedByPolicy) {
                return PassportVerificationCheck(status: .notChecked, reason: .skipped)
            }
            if dataGroupsRead[.DG15] != nil || dataGroupsRead[.COM] != nil || dg15Statuses.contains(.unsupported) {
                return PassportVerificationCheck(status: .notChecked, reason: .notSupported)
            }
            if dg15Statuses.contains(.failed) {
                return PassportVerificationCheck(status: .failed, reason: .attemptedFailed)
            }
            if dg15Statuses.contains(.advertised) || dg15Statuses.contains(.requested) {
                return PassportVerificationCheck(status: .notChecked, reason: .skipped)
            }
            return PassportVerificationCheck(status: .notChecked, reason: .notRequested)
        }
        if activeAuthenticationPassed {
            return PassportVerificationCheck(status: .passed, reason: .passed)
        }
        if !activeAuthenticationAttempted {
            return PassportVerificationCheck(status: .notChecked, reason: .skipped)
        }
        return PassportVerificationCheck(status: .failed, reason: .attemptedFailed)
    }

    private func verificationCheckForChipAuthentication() -> PassportVerificationCheck {
        guard isChipAuthenticationSupported else {
            let dg14Statuses = dataGroupReadReports
                .filter { $0.dataGroup == .DG14 }
                .map(\.status)

            if dg14Statuses.contains(.skippedByProfile) || dg14Statuses.contains(.blockedByPolicy) {
                return PassportVerificationCheck(status: .notChecked, reason: .skipped)
            }
            if dataGroupsRead[.DG14] != nil || dataGroupsRead[.COM] != nil || dg14Statuses.contains(.unsupported) {
                return PassportVerificationCheck(status: .notChecked, reason: .notSupported)
            }
            if dg14Statuses.contains(.failed) {
                return PassportVerificationCheck(status: .failed, reason: .attemptedFailed)
            }
            if dg14Statuses.contains(.advertised) || dg14Statuses.contains(.requested) {
                return PassportVerificationCheck(status: .notChecked, reason: .skipped)
            }
            return PassportVerificationCheck(status: .notChecked, reason: .notRequested)
        }
        switch chipAuthenticationStatus {
        case .notDone:
            return PassportVerificationCheck(status: .notChecked, reason: .skipped)
        case .success:
            return PassportVerificationCheck(status: .passed, reason: .passed)
        case .failed:
            return PassportVerificationCheck(status: .failed, reason: .attemptedFailed)
        }
    }

    private func dataGroupVerificationCoverage() -> [PassportDataGroupVerificationCoverage] {
        var coverage: [PassportDataGroupVerificationCoverage] = []
        let readIds = Set(dataGroupsRead.keys).filter { $0 != .COM && $0 != .SOD }
        let hashedIds = sodHashDataGroupIds
        let ids = Array(readIds.union(hashedIds)).sorted { $0.logicalDataGroupNumber < $1.logicalDataGroupNumber }

        for id in ids {
            if let hash = dataGroupHashes[id] {
                coverage.append(PassportDataGroupVerificationCoverage(
                    dataGroup: id,
                    status: hash.match ? .coveredAndMatched : .coveredButMismatched
                ))
            } else if readIds.contains(id) {
                coverage.append(PassportDataGroupVerificationCoverage(dataGroup: id, status: .readButNotCovered))
            } else {
                coverage.append(PassportDataGroupVerificationCoverage(dataGroup: id, status: .coveredButNotRead))
            }
        }

        return coverage
    }
}

@available(iOS 13, macOS 10.15, *)
private extension Bool {
    var verificationStatus: PassportVerificationStatus {
        self ? .passed : .failed
    }
}

@available(iOS 13, macOS 10.15, *)
private extension DataGroupId {
    var logicalDataGroupNumber: Int {
        switch self {
        case .DG1: return 1
        case .DG2: return 2
        case .DG3: return 3
        case .DG4: return 4
        case .DG5: return 5
        case .DG6: return 6
        case .DG7: return 7
        case .DG8: return 8
        case .DG9: return 9
        case .DG10: return 10
        case .DG11: return 11
        case .DG12: return 12
        case .DG13: return 13
        case .DG14: return 14
        case .DG15: return 15
        case .DG16: return 16
        case .COM: return 0
        case .SOD: return 17
        case .Unknown: return Int.max
        }
    }
}

@available(iOS 13, macOS 10.15, *)
private extension PassportAuthenticationStatus {
    var verificationStatus: PassportVerificationStatus {
        switch self {
        case .notDone:
            return .notChecked
        case .success:
            return .passed
        case .failed:
            return .failed
        }
    }
}

private extension URL {
    var privacySafeFileModificationDate: Date? {
        try? resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate
    }
}
