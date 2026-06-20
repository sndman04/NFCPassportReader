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
class NFCPassportModel {
    
    public var documentType : String { return String( passportDataElements?["5F03"]?.first ?? "?" ) }
    public var documentSubType : String { return String( passportDataElements?["5F03"]?.last ?? "?" ) }
    public var documentNumber : String { return (passportDataElements?["5A"] ?? "?").replacingOccurrences(of: "<", with: "" ) }
    public var issuingAuthority : String { return passportDataElements?["5F28"] ?? "?" }
    public var documentExpiryDate : String { return passportDataElements?["59"] ?? "?" }
    public var dateOfBirth : String { return passportDataElements?["5F57"] ?? "?" }
    public var gender : String { return passportDataElements?["5F35"] ?? "?" }
    public var nationality : String { return passportDataElements?["5F2C"] ?? "?" }
    
    public var lastName : String {
        return names[0].replacingOccurrences(of: "<", with: " " )
    }
    
    public var firstName : String {
        var name = ""
        for i in 1 ..< names.count {
            let fn = names[i].replacingOccurrences(of: "<", with: " " ).trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
            name += fn + " "
        }
        return name.trimmingCharacters(in: CharacterSet.whitespacesAndNewlines)
    }
    
    // Extract fields from DG11 if present
    private var names : [String] {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let fullName = dg11.fullName?.components(separatedBy: "<<") else { return (passportDataElements?["5B"] ?? "?").components(separatedBy: "<<") }
        return fullName
    }
    
    public var placeOfBirth : String? {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let placeOfBirth = dg11.placeOfBirth else { return nil }
        return placeOfBirth
    }
    
    /// residence address
    public var residenceAddress : String? {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let address = dg11.address else { return nil }
        return address
    }
    
    /// phone number
    public var phoneNumber : String? {
        guard let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
              let telephone = dg11.telephone else { return nil }
        return telephone
    }
    
    /// personal number
    public var personalNumber : String? {
        if let dg11 = dataGroupsRead[.DG11] as? DataGroup11,
           let personalNumber = dg11.personalNumber { return personalNumber }
        
        return (passportDataElements?["53"] ?? "?").replacingOccurrences(of: "<", with: "" )
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
        
    
    public init() {
        
    }
    
    func addDataGroup(_ id : DataGroupId, dataGroup: DataGroup ) {
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
        dataGroupReadReports.removeAll(keepingCapacity: false)
        cardAccess = nil
        cardSecurity = nil
        paceChipAuthenticationMappingResult = nil
        certificateSigningGroups.removeAll(keepingCapacity: false)
        activeAuthenticationChallenge.removeAll(keepingCapacity: false)
        activeAuthenticationSignature.removeAll(keepingCapacity: false)
    }

    func recordDataGroupReadStatus(_ status: PassportDataGroupReadStatus, for id: DataGroupId) {
        guard id != .Unknown else { return }
        let report = PassportDataGroupReadReport(dataGroup: id, status: status)
        if !dataGroupReadReports.contains(report) {
            dataGroupReadReports.append(report)
        }
    }

    func getHashesForDatagroups( hashAlgorythm: String ) -> [DataGroupId:[UInt8]]  {
        var ret = [DataGroupId:[UInt8]]()
        
        for (key, value) in dataGroupsRead {
            if hashAlgorythm == "SHA1" {
                ret[key] = calcSHA1Hash(value.body)
            } else if hashAlgorythm == "SHA224" {
                ret[key] = calcSHA224Hash(value.body)
            } else if hashAlgorythm == "SHA256" {
                ret[key] = calcSHA256Hash(value.body)
            } else if hashAlgorythm == "SHA384" {
                ret[key] = calcSHA384Hash(value.body)
            } else if hashAlgorythm == "SHA512" {
                ret[key] = calcSHA512Hash(value.body)
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
        self.activeAuthenticationChallenge = challenge
        self.activeAuthenticationSignature = signature

        // Get AA Public key
        self.activeAuthenticationPassed = false
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
        } catch {
            signedData = try sod.getEncapsulatedContent()
        }
                
        // Now Verify passport data by comparing compare Hashes in SOD against
        // computed hashes to ensure data not been tampered with
        passportDataNotTampered = false
        let (sodHashAlgorythm, sodHashes) = try parseSODSignatureContent(data: signedData)
        
        var errorSummaries: [String] = []
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
        }
        
        if !errorSummaries.isEmpty {
            throw PassiveAuthenticationError.InvalidDataGroupHash(errorSummaries.joined(separator: "; "))
        }
        passportDataNotTampered = true
    }

    private func verifySODAndReturnEncapsulatedContent(sod: SOD, preferCMSVerification: Bool) throws -> Data {
        let firstVerifier: (SOD) throws -> Data = preferCMSVerification
            ? OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS
            : OpenSSLUtils.verifyAndReturnSODEncapsulatedData
        let secondVerifier: (SOD) throws -> Data = preferCMSVerification
            ? OpenSSLUtils.verifyAndReturnSODEncapsulatedData
            : OpenSSLUtils.verifyAndReturnSODEncapsulatedDataUsingCMS

        do {
            return try firstVerifier(sod)
        } catch {
            return try secondVerifier(sod)
        }
    }
    
    
    /// Parses the structured LDS Security Object and extracts the digest algorithm and data-group hashes.
    /// - Parameter data: DER-encoded LDS Security Object content.
    /// - Returns: The digest algorithm and a dictionary of hashes for SOD-listed data groups.
    func parseSODSignatureContent(data: Data) throws -> (String, [DataGroupId : String]) {
        let root = try SimpleASN1Node.parse([UInt8](data))
        guard root.tag == 0x30,
              root.children.count >= 3,
              let digestAlgorithmOID = root.children[1].children.first?.objectIdentifier,
              let digestAlgorithm = hashAlgorithmName(for: digestAlgorithmOID) else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to parse structured SOD hashes")
        }

        let dataGroupHashValues = root.children[2]
        guard dataGroupHashValues.tag == 0x30 else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to parse structured SOD hashes")
        }

        var sodHashes: [DataGroupId: String] = [:]
        for hashValue in dataGroupHashValues.children {
            guard hashValue.children.count >= 2,
                  let dataGroupNumber = hashValue.children[0].integerValue,
                  let dataGroupId = dataGroupId(forSODNumber: dataGroupNumber),
                  hashValue.children[1].tag == 0x04 else {
                throw PassiveAuthenticationError.UnableToParseSODHashes("Invalid data group hash structure")
            }

            sodHashes[dataGroupId] = binToHexRep(hashValue.children[1].value)
        }

        guard !sodHashes.isEmpty else {
            throw PassiveAuthenticationError.UnableToParseSODHashes("Unable to extract hashes")
        }

        return (digestAlgorithm, sodHashes)
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
            if dg15Statuses.contains(.advertised) || dg15Statuses.contains(.requested) || dg15Statuses.contains(.failed) {
                return PassportVerificationCheck(status: .notChecked, reason: .skipped)
            }
            if dataGroupsRead[.DG15] != nil || dataGroupsRead[.COM] != nil || dg15Statuses.contains(.unsupported) {
                return PassportVerificationCheck(status: .notChecked, reason: .notSupported)
            }
            return PassportVerificationCheck(status: .notChecked, reason: .notRequested)
        }
        if activeAuthenticationPassed {
            return PassportVerificationCheck(status: .passed, reason: .passed)
        }
        if activeAuthenticationChallenge.isEmpty && activeAuthenticationSignature.isEmpty {
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
            if dg14Statuses.contains(.advertised) || dg14Statuses.contains(.requested) || dg14Statuses.contains(.failed) {
                return PassportVerificationCheck(status: .notChecked, reason: .skipped)
            }
            if dataGroupsRead[.DG14] != nil || dataGroupsRead[.COM] != nil || dg14Statuses.contains(.unsupported) {
                return PassportVerificationCheck(status: .notChecked, reason: .notSupported)
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
        let hashedIds = Set(dataGroupHashes.keys)
        let ids = Array(readIds.union(hashedIds)).sorted { $0.rawValue < $1.rawValue }

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
