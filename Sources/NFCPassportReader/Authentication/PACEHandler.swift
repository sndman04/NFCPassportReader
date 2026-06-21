//
//  PACEHandler.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 03/03/2021.
//

import Foundation
import OpenSSL
import OpenSSLCompat
import CryptoTokenKit

#if !os(macOS)
import CoreNFC
import CryptoKit

@available(iOS 15, *)
private enum PACEHandlerError {
    case DHKeyAgreementError(String)
    case ECDHKeyAgreementError(String)
    
    var value: String {
        switch self {
            case .DHKeyAgreementError(let errMsg): return errMsg
            case .ECDHKeyAgreementError(let errMsg): return errMsg

        }
    }
}

@available(iOS 15, *)
extension PACEHandlerError: LocalizedError {
    var errorDescription: String? {
        return NSLocalizedString(value, comment: "PACEHandlerError")
    }
}

@available(iOS 15, *)
@MainActor
class PACEHandler {
    
    
    var tagReader : TagReader
    var paceInfo : PACEInfo
    
    var isPACESupported : Bool = false
    var paceError : String = ""
    
    // Params used
    private var paceKey : [UInt8] = []
    private var paceKeyType : UInt8 = 0
    private var paceOID : String = ""
    private var parameterSpec : Int32 = -1
    private var mappingType : PACEMappingType?
    private var agreementAlg : String = ""
    private var cipherAlg : String = ""
    private var digestAlg : String = ""
    private var keyLength : Int = -1
    private var chipMappingPublicKey: [UInt8] = []

    var chipAuthenticationMappingResult: PACEChipAuthenticationMappingResult?
    
    init(cardAccess : CardAccess, tagReader: TagReader) throws {
        self.tagReader = tagReader
        
        guard let pi = cardAccess.preferredPACEInfo else {
            throw NFCPassportReaderError.NotYetSupported( "PACE not supported" )
        }

        self.paceInfo = pi
        isPACESupported = true
    }

    init(paceInfo: PACEInfo, tagReader: TagReader) {
        self.tagReader = tagReader
        self.paceInfo = paceInfo
        isPACESupported = true
    }

    isolated deinit {
        removeSensitiveData()
    }

    func removeSensitiveData() {
        removeSensitiveData(clearMappingResult: true)
    }

    private func removeSensitiveData(clearMappingResult: Bool) {
        paceKey.removeAll(keepingCapacity: false)
        paceKeyType = 0
        paceOID.removeAll(keepingCapacity: false)
        parameterSpec = -1
        mappingType = nil
        agreementAlg.removeAll(keepingCapacity: false)
        cipherAlg.removeAll(keepingCapacity: false)
        digestAlg.removeAll(keepingCapacity: false)
        keyLength = -1
        chipMappingPublicKey.removeAll(keepingCapacity: false)
        if clearMappingResult {
            chipAuthenticationMappingResult = nil
        }
    }
    
    func doPACE(mrzKey: String) async throws {
        try await doPACE(accessKey: mrzKey, keyReference: .mrz)
    }

    func doPACE(accessKey: String, keyReference: PassportPACEKeyReference) async throws {
        defer { removeSensitiveData(clearMappingResult: false) }

        guard isPACESupported else {
            throw NFCPassportReaderError.NotYetSupported( "PACE not supported" )
        }
        
        paceOID = paceInfo.getObjectIdentifier()
        parameterSpec = try paceInfo.getParameterSpec()
        
        mappingType = try paceInfo.getMappingType()  // Either GM, CAM, or IM.
        agreementAlg = try paceInfo.getKeyAgreementAlgorithm()  // Either DH or ECDH.
        cipherAlg  = try paceInfo.getCipherAlgorithm()  // Either DESede or AES.
        digestAlg = try paceInfo.getDigestAlgorithm()  // Either SHA-1 or SHA-256.
        keyLength = try paceInfo.getKeyLength()  // Get key length  the enc cipher. Either 128, 192, or 256.

        paceKeyType = keyReference.rawValue
        paceKey = try createPaceKey(from: accessKey, keyReference: keyReference)

        // First start the initial auth call
        _ = try await tagReader.sendMSESetATMutualAuth(oid: paceOID, keyType: paceKeyType)
            
        let decryptedNonce = try await self.doStep1()

        let ephemeralParams = try await self.doStep2(passportNonce: decryptedNonce)
        defer { EVP_PKEY_free( ephemeralParams ) }

        let (ephemeralKeyPair, passportPublicKey) = try await self.doStep3KeyExchange(ephemeralParams: ephemeralParams)
        defer { EVP_PKEY_free(ephemeralKeyPair); EVP_PKEY_free(passportPublicKey) }

        let (encKey, macKey) = try await self.doStep4KeyAgreement( pcdKeyPair: ephemeralKeyPair, passportPublicKey: passportPublicKey)
        try self.paceCompleted( ksEnc: encKey, ksMac: macKey )
    }
    
    /// Handles an error during the PACE process
    /// Logs and stoes the error and returns false to the caller
    /// - Parameters:
    ///   - stage: Where in the PACE process the error occurred
    ///   - error: The error message
    func handleError( _ stage: String, _ error: String, needToTerminateGA: Bool = false ) {
        self.paceError = "\(stage) - \(error)"
        //self.completedHandler?( false )

/*
        if needToTerminateGA {
            // This is to fix some passports that don't automatically terminate command chaining!
            // No idea if this is the correct way to do it but testing.....
            let terminateGA = wrapDO(b:0x83, arr:[0x00])
            tagReader.sendGeneralAuthenticate(data:terminateGA, isLast:true, completed: { [weak self] response, error in
                self?.completedHandler?( false )
            })
        } else {
            self.completedHandler?( false )
        }
*/
    }
    
    /// Performs PACE Step 1- receives an encrypted nonce from the passport and decrypts it with the PACE key.
    func doStep1() async throws -> [UInt8] {
        let response = try await tagReader.sendGeneralAuthenticate(data: [], isLast: false)
            
        let data = response.data
        let encryptedNonce = try unwrapDO(tag: 0x80, wrappedData: data)

        let decryptedNonce: [UInt8]
        if self.cipherAlg == "DESede" {
            let iv = [UInt8](repeating:0, count: 8)
            decryptedNonce = tripleDESDecrypt(key: self.paceKey, message: encryptedNonce, iv: iv)
        } else if self.cipherAlg == "AES" {
            let iv = [UInt8](repeating:0, count: 16)
            decryptedNonce = AESDecrypt(key: self.paceKey, message: encryptedNonce, iv: iv)
        } else {
            throw NFCPassportReaderError.UnsupportedCipherAlgorithm
        }
        guard !decryptedNonce.isEmpty else {
            throw NFCPassportReaderError.PACEError("Step1 Nonce", "Unable to decrypt passport nonce")
        }
        return decryptedNonce
    }
    
    
    /// Performs PACE Step 2 - computes ephemeral parameters by mapping the nonce received from the passport
    ///  (and if IM used the nonce generated by us)
    ///
    /// Using the supported
    /// - Parameters:
    ///   - passportNonce: The decrypted nonce received from the passport
    func doStep2( passportNonce: [UInt8]) async throws -> OpaquePointer {
        guard let mappingType else {
            throw NFCPassportReaderError.PACEError("Step2 Mapping", "PACE mapping type missing")
        }

        switch(mappingType) {
            case .GM:
                return try await doPACEStep2GM(passportNonce: passportNonce)
            case .CAM:
                return try await doPACEStep2GM(passportNonce: passportNonce)
            case .IM:
                return try await doPACEStep2IM(passportNonce: passportNonce)
        }

    }
    
    /// Performs PACEStep 2 using Generic Mapping
    ///
    /// Using the supported
    /// - Parameters:
    ///   - passportNonce: The decrypted nonce received from the passport
    func doPACEStep2GM(passportNonce : [UInt8]) async throws -> OpaquePointer {
        
        let mappingKey : OpaquePointer
        mappingKey = try self.paceInfo.createMappingKey( )
        defer { EVP_PKEY_free(mappingKey) }

        guard let pcdMappingEncodedPublicKey = OpenSSLUtils.getPublicKeyData(from: mappingKey) else {
            throw NFCPassportReaderError.PACEError( "Step2GM", "Unable to get public key from mapping key")
        }
        let step2Data = wrapDO(b:0x81, arr:pcdMappingEncodedPublicKey)
        let response = try await tagReader.sendGeneralAuthenticate(data:step2Data, isLast:false)

        let piccMappingEncodedPublicKey = try unwrapDO(tag: 0x82, wrappedData: response.data)
        if mappingType == .CAM {
            chipMappingPublicKey = piccMappingEncodedPublicKey
        }

        // Do mapping agreement

        // First, Convert nonce to BIGNUM
        guard let bn_nonce = BN_bin2bn(passportNonce, Int32(passportNonce.count), nil) else {
            throw NFCPassportReaderError.PACEError( "Step2GM", "Unable to convert picc nonce to bignum" )
        }
        defer { BN_free(bn_nonce) }

        // ephmeralParams are free'd in stage 3
        let ephemeralParams : OpaquePointer
        if self.agreementAlg == "DH" {
            ephemeralParams = try self.doDHMappingAgreement(mappingKey: mappingKey, passportPublicKeyData: piccMappingEncodedPublicKey, nonce: bn_nonce )
        } else if self.agreementAlg == "ECDH" {
            ephemeralParams = try self.doECDHMappingAgreement(mappingKey: mappingKey, passportPublicKeyData: piccMappingEncodedPublicKey, nonce: bn_nonce )
        } else {
            throw NFCPassportReaderError.PACEError( "Step2GM", "Unsupported agreement algorithm" )
        }

        return ephemeralParams
    }
    
    func doPACEStep2IM( passportNonce: [UInt8] ) async throws -> OpaquePointer {
        let terminalNonce = generateRandomUInt8Array(integratedMappingNonceLength())
        let step2Data = wrapDO(b: 0x81, arr: terminalNonce)
        let response = try await tagReader.sendGeneralAuthenticate(data: step2Data, isLast: false)
        let chipMappingData = try unwrapDO(tag: 0x82, wrappedData: response.data)
        guard chipMappingData.isEmpty else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Unexpected chip mapping data")
        }

        let mappedField = try integratedMappingField(passportNonce: passportNonce, terminalNonce: terminalNonce)
        let domainKey = try self.paceInfo.createMappingKey()
        defer { EVP_PKEY_free(domainKey) }

        var field = mappedField
        if self.agreementAlg == "DH" {
            guard let ephemeralParams = NFCPRCreateDHIntegratedMappedParameters(domainKey, &field, field.count) else {
                throw NFCPassportReaderError.PACEError("Step2IM", "Unable to configure DH mapped parameters")
            }
            return ephemeralParams
        } else if self.agreementAlg == "ECDH" {
            guard let ephemeralParams = NFCPRCreateECDHIntegratedMappedParameters(domainKey, &field, field.count) else {
                throw NFCPassportReaderError.PACEError("Step2IM", "Unable to configure ECDH mapped parameters")
            }
            return ephemeralParams
        } else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Unsupported agreement algorithm")
        }
    }
    
    /// Generates an ephemeral public/private key pair based on mapping parameters from step 2, and then sends
    /// the public key to the passport and receives its ephmeral public key in exchange
    /// - Parameters:
    ///     - ephemeralParams: The ehpemeral mapping keys generated by step2
    /// - Returns:
///         - Tuple of Generated Ephemeral KeyPair and the Passport's public key
    func doStep3KeyExchange(ephemeralParams: OpaquePointer) async throws -> (OpaquePointer, OpaquePointer) {
        var ephKeyPair: OpaquePointer? = try OpenSSLUtils.generateKeyPair(fromParameters: ephemeralParams)
        guard let ephemeralKeyPair = ephKeyPair else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Unable to create ephemeral key pair" )
        }
        defer { EVP_PKEY_free(ephKeyPair) }

        guard let publicKey = OpenSSLUtils.getPublicKeyData( from: ephemeralKeyPair ) else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Unable to get public key from ephermeral key pair" )
        }

        // exchange public keys
        let step3Data = wrapDO(b:0x83, arr:publicKey)
        let response = try await tagReader.sendGeneralAuthenticate(data:step3Data, isLast:false)
        guard let passportEncodedPublicKey = try? unwrapDO(tag: 0x84, wrappedData: response.data),
              let passportPublicKey = OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: passportEncodedPublicKey, params: ephemeralKeyPair) else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyEx", "Unable to decode passports ephemeral key" )
        }
        defer { ephKeyPair = nil } // prevent free to return the value on success path
        return (ephemeralKeyPair, passportPublicKey)
    }
    
    /// This performs PACE Step 4 - Key Agreement.
    /// Here the shared secret is computed from our ephemeral private key and the passports ephemeral public key
    /// The new secure messaging (ksEnc and ksMac) keys are computed from the shared secret
    /// An authentication token is generated from the passports public key and the computed ksMac key
    /// Then, the authetication token is send to the passport, it returns its own computed authentication token
    /// We then compute an expected authentication token from the ksMac key and our ephemeral public key
    /// Finally we compare the recieved auth token to the expected token and if they are the same then PACE has succeeded!
    /// - Parameters:
    ///     - pcdKeyPair: our ephemeral key pair
    ///     - passportPublicKey: passports ephemeral public key
    /// - Returns:
    ///         - Tuple of KSEnc KSMac
    func doStep4KeyAgreement( pcdKeyPair: OpaquePointer, passportPublicKey: OpaquePointer) async throws -> ([UInt8], [UInt8]) {
        let sharedSecret = try OpenSSLUtils.computeSharedSecret(privateKeyPair: pcdKeyPair, publicKey: passportPublicKey)
        guard !sharedSecret.isEmpty else {
            throw NFCPassportReaderError.PACEError("Step3 KeyAgreement", "Unable to derive shared secret")
        }

        let gen = SecureMessagingSessionKeyGenerator()
        let encKey = try gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .ENC_MODE)
        let macKey = try gen.deriveKey(keySeed: sharedSecret, cipherAlgName: cipherAlg, keyLength: keyLength, mode: .MAC_MODE)

        // Step 4 - generate authentication token
        guard let pcdAuthToken = try? generateAuthenticationToken( publicKey: passportPublicKey, macKey: macKey) else {
            throw NFCPassportReaderError.PACEError( "Step3 KeyAgreement", "Unable to generate authentication token using passports public key" )
        }
        let step4Data = wrapDO(b:0x85, arr:pcdAuthToken)
        let response = try await tagReader.sendGeneralAuthenticate(data:step4Data, isLast:true)
            
        guard let tvlResp = TKBERTLVRecord.sequenceOfRecords(from: Data(response.data)),
              let tokenRecord = tvlResp.first,
              tokenRecord.tag == 0x86 else {
            throw NFCPassportReaderError.PACEError("Step3 KeyAgreement", "Passport authentication token missing")
        }

        // Calculate expected authentication token
        let expectedAuthenticationToken = try self.generateAuthenticationToken( publicKey: pcdKeyPair, macKey: macKey)

        let receivedAuthenticationToken = [UInt8](tokenRecord.value)

        guard receivedAuthenticationToken == expectedAuthenticationToken else {
            throw NFCPassportReaderError.PACEError("Step3 KeyAgreement", "Passport authentication token mismatch")
        }

        if mappingType == .CAM {
            guard let encryptedCAMData = tvlResp.first(where: { $0.tag == 0x8A })?.value,
                  !encryptedCAMData.isEmpty else {
                throw NFCPassportReaderError.PACEError("Step3 KeyAgreement", "PACE CAM data missing")
            }

            chipAuthenticationMappingResult = try PACEChipAuthenticationMappingResult(
                mappingPublicKey: chipMappingPublicKey,
                encryptedChipAuthenticationData: [UInt8](encryptedCAMData),
                encryptionKey: encKey
            )
        }
        
        // We're done!
        return (encKey, macKey)
    }
    
    /// Called once PACE has completed with the newly generated ksEnc and ksMac keys for restarting secure messaging
    /// - Parameters:
    ///   - ksEnc: the computed encryption key derived from the key agreement
    ///   - ksMac: the computed mac key derived from the key agreement
    func paceCompleted( ksEnc: [UInt8], ksMac: [UInt8] ) throws {
        // Restart secure messaging
        let ssc = withUnsafeBytes(of: 0.bigEndian, Array.init)
        if (cipherAlg.hasPrefix("DESede")) {
            let sm = SecureMessaging(encryptionAlgorithm: .DES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader.secureMessaging = sm
        } else if (cipherAlg.hasPrefix("AES")) {
            let sm = SecureMessaging(encryptionAlgorithm: .AES, ksenc: ksEnc, ksmac: ksMac, ssc: ssc)
            tagReader.secureMessaging = sm
        } else {
            throw NFCPassportReaderError.UnsupportedCipherAlgorithm
        }
    }
}

// MARK - PACEHandler Utility functions
@available(iOS 15, *)
extension PACEHandler {
    
    /// Does the DH key Mapping agreement
    /// - Parameter mappingKey - Pointer to an EVP_PKEY structure containing the mapping key
    /// - Parameter passportPublicKeyData - byte array containing the publick key read from the passport
    /// - Parameter nonce - Pointer to an BIGNUM structure containing the unencrypted nonce
    /// - Returns the EVP_PKEY containing the mapped ephemeral parameters
    func doDHMappingAgreement( mappingKey : OpaquePointer, passportPublicKeyData: [UInt8], nonce: OpaquePointer ) throws -> OpaquePointer {
        var publicKey = passportPublicKeyData
        guard let ephemeralParams = NFCPRCreateDHMappedParameters(mappingKey, &publicKey, publicKey.count, nonce) else {
            throw PACEHandlerError.DHKeyAgreementError( "Unable to set ephemeral parameters" )
        }
        return ephemeralParams
    }
    
    /// Does the ECDH key Mapping agreement
    /// - Parameter mappingKey - Pointer to an EVP_PKEY structure containing the mapping key
    /// - Parameter passportPublicKeyData - byte array containing the publick key read from the passport
    /// - Parameter nonce - Pointer to an BIGNUM structure containing the unencrypted nonce
    /// - Returns the EVP_PKEY containing the mapped ephemeral parameters
    func doECDHMappingAgreement( mappingKey : OpaquePointer, passportPublicKeyData: [UInt8], nonce: OpaquePointer ) throws -> OpaquePointer {
        var publicKey = passportPublicKeyData
        guard let ephemeralParams = NFCPRCreateECDHMappedParameters(mappingKey, &publicKey, publicKey.count, nonce) else {
            throw PACEHandlerError.ECDHKeyAgreementError( "Unable to configure new ephemeral params" )
        }
        return ephemeralParams
    }
    
    /// Generate Authentication token from a publicKey and and a mac key
    /// - Parameters:
    ///   - publicKey: An EVP_PKEY structure containing a public key data which will be used to generate the auth code
    ///   - macKey: The mac key derived from the key agreement
    /// - Throws: An error if we are unable to encode the public key data
    /// - Returns: The authentication token (8 bytes)
    func generateAuthenticationToken( publicKey: OpaquePointer, macKey: [UInt8] ) throws -> [UInt8] {
        var encodedPublicKeyData = try encodePublicKey(oid:self.paceOID, key:publicKey)
        
        if cipherAlg == "DESede" {
            // If DESede (3DES), we need to pad the data
            encodedPublicKeyData = pad(encodedPublicKeyData, blockSize: 8)
        }

        let maccedPublicKeyDataObject = mac(algoName: cipherAlg == "DESede" ? .DES : .AES, key: macKey, msg: encodedPublicKeyData)
        guard maccedPublicKeyDataObject.count >= 8 else {
            throw NFCPassportReaderError.PACEError("Authentication Token", "Unable to calculate authentication token")
        }

        // Take 8 bytes for auth token
        let authToken = [UInt8](maccedPublicKeyDataObject[0..<8])
        return authToken
    }
    
    /// Encodes a PublicKey as an TLV strucuture based on TR-SAC 1.01 4.5.1 and 4.5.2
    /// - Parameters:
    ///   - oid: The object identifier specifying the key type
    ///   - key: The ECP_PKEY public key to encode
    /// - Throws: Error if unable to encode
    /// - Returns: the encoded public key in tlv format
    func encodePublicKey( oid : String, key : OpaquePointer ) throws -> [UInt8] {
        let encodedOid = oidToBytes(oid:oid, replaceTag: false)
        guard let pubKeyData = OpenSSLUtils.getPublicKeyData(from: key) else {
            throw NFCPassportReaderError.InvalidDataPassed("Unable to get public key data")
        }

        let keyType = EVP_PKEY_get_base_id( key )
        let tag : TKTLVTag
        if keyType == EVP_PKEY_DH || keyType == EVP_PKEY_DHX {
            tag = 0x84
        } else {
            tag = 0x86
        }

        guard let encOid = TKBERTLVRecord(from: Data(encodedOid)) else {
            throw NFCPassportReaderError.InvalidASN1Value
        }
        let encPub = TKBERTLVRecord(tag:tag, value: Data(pubKeyData))
        let record = TKBERTLVRecord(tag: 0x7F49, records:[encOid, encPub])
        let data = record.data

        return [UInt8](data)
    }

    /// Computes a key seed based on an MRZ key
    /// - Parameter the mrz key
    /// - Returns a encoded key based on the mrz key that can be used for PACE
    func createPaceKey(from accessKey: String, keyReference: PassportPACEKeyReference = .mrz) throws -> [UInt8] {
        let buf: [UInt8] = Array(accessKey.utf8)
        let hash = calcSHA1Hash(buf)
        
        let smskg = SecureMessagingSessionKeyGenerator()
        let key = try smskg.deriveKey(keySeed: hash, cipherAlgName: cipherAlg, keyLength: keyLength, nonce: nil, mode: .PACE_MODE, paceKeyReference: keyReference.rawValue)
        return key
    }

    func integratedMappingNonceLength() -> Int {
        if cipherAlg == "DESede" {
            return 16
        }
        return max(keyLength / 8, 16)
    }

    func integratedMappingField(passportNonce: [UInt8], terminalNonce: [UInt8]) throws -> [UInt8] {
        try PACEHandler.integratedMappingField(
            passportNonce: passportNonce,
            terminalNonce: terminalNonce,
            cipherAlg: cipherAlg,
            keyLength: keyLength,
            primeBitLength: integratedMappingPrimeBitLength()
        )
    }

    nonisolated static func integratedMappingField(
        passportNonce: [UInt8],
        terminalNonce: [UInt8],
        cipherAlg: String,
        keyLength: Int,
        primeBitLength: Int
    ) throws -> [UInt8] {
        let nonceLength = integratedMappingNonceLength(cipherAlg: cipherAlg, keyLength: keyLength)
        let blockLength = integratedMappingInputBlockLength(cipherAlg: cipherAlg, keyLength: keyLength)
        guard passportNonce.count == blockLength,
              terminalNonce.count == nonceLength else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Invalid Integrated Mapping nonce length")
        }

        let blockBitLength = blockLength * 8
        let blocksRequired = (primeBitLength + 64 + blockBitLength - 1) / blockBitLength
        let c0: [UInt8]
        let c1: [UInt8]
        if blockLength == 16 {
            c0 = hexRepToBin("A668892A7C41E3CA739F40B057D85904")
            c1 = hexRepToBin("A4E136AC725F738B01C1F60217C188AD")
        } else {
            c0 = hexRepToBin("D463D65234124EF7897054986DCA0A174E28DF758CBAA03F240616414D5A1676")
            c1 = hexRepToBin("54BD7255F0AAF831BEC3423FCF39D69B6CBF066677D0FAAE5AADD99DF8E53517")
        }

        var currentKey = try integratedMappingEncrypt(
            key: terminalNonce,
            message: passportNonce,
            cipherAlg: cipherAlg
        )
        currentKey = integratedMappingTruncatedKey(currentKey, cipherAlg: cipherAlg, keyLength: keyLength)

        var output: [UInt8] = []
        output.reserveCapacity(blocksRequired * blockLength)
        for _ in 0..<blocksRequired {
            let block = try integratedMappingEncrypt(key: currentKey, message: c1, cipherAlg: cipherAlg)
            output.append(contentsOf: block)
            currentKey = try integratedMappingEncrypt(key: currentKey, message: c0, cipherAlg: cipherAlg)
            currentKey = integratedMappingTruncatedKey(currentKey, cipherAlg: cipherAlg, keyLength: keyLength)
        }

        return output
    }

    private func integratedMappingInputBlockLength() -> Int {
        PACEHandler.integratedMappingInputBlockLength(cipherAlg: cipherAlg, keyLength: keyLength)
    }

    nonisolated private static func integratedMappingInputBlockLength(cipherAlg: String, keyLength: Int) -> Int {
        if cipherAlg == "AES", keyLength > 128 {
            return 32
        }
        return 16
    }

    private func integratedMappingTruncatedKey(_ key: [UInt8]) -> [UInt8] {
        PACEHandler.integratedMappingTruncatedKey(key, cipherAlg: cipherAlg, keyLength: keyLength)
    }

    nonisolated private static func integratedMappingNonceLength(cipherAlg: String, keyLength: Int) -> Int {
        if cipherAlg == "DESede" {
            return 16
        }
        return max(keyLength / 8, 16)
    }

    nonisolated private static func integratedMappingTruncatedKey(_ key: [UInt8], cipherAlg: String, keyLength: Int) -> [UInt8] {
        let requiredLength = integratedMappingNonceLength(cipherAlg: cipherAlg, keyLength: keyLength)
        guard key.count > requiredLength else {
            return key
        }
        return Array(key.prefix(requiredLength))
    }

    private func integratedMappingEncrypt(key: [UInt8], message: [UInt8]) throws -> [UInt8] {
        try PACEHandler.integratedMappingEncrypt(key: key, message: message, cipherAlg: cipherAlg)
    }

    nonisolated private static func integratedMappingEncrypt(key: [UInt8], message: [UInt8], cipherAlg: String) throws -> [UInt8] {
        let ivLength = cipherAlg == "DESede" ? 8 : 16
        let iv = [UInt8](repeating: 0, count: ivLength)
        let encrypted: [UInt8]
        if cipherAlg == "DESede" {
            encrypted = tripleDESEncrypt(key: key, message: message, iv: iv)
        } else if cipherAlg == "AES" {
            encrypted = AESEncrypt(key: key, message: message, iv: iv)
        } else {
            throw NFCPassportReaderError.UnsupportedCipherAlgorithm
        }
        guard encrypted.count == message.count else {
            throw NFCPassportReaderError.PACEError("Step2IM", "Unable to calculate Integrated Mapping field")
        }
        return encrypted
    }

    private func integratedMappingPrimeBitLength() throws -> Int {
        switch paceInfo.getParameterId() {
        case PACEInfo.PARAM_ID_GFP_1024_160:
            return 1024
        case PACEInfo.PARAM_ID_GFP_2048_224, PACEInfo.PARAM_ID_GFP_2048_256:
            return 2048
        case PACEInfo.PARAM_ID_ECP_NIST_P192_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P192_R1:
            return 192
        case PACEInfo.PARAM_ID_ECP_NIST_P224_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P224_R1:
            return 224
        case PACEInfo.PARAM_ID_ECP_NIST_P256_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P256_R1:
            return 256
        case PACEInfo.PARAM_ID_ECP_BRAINPOOL_P320_R1:
            return 320
        case PACEInfo.PARAM_ID_ECP_NIST_P384_R1, PACEInfo.PARAM_ID_ECP_BRAINPOOL_P384_R1:
            return 384
        case PACEInfo.PARAM_ID_ECP_BRAINPOOL_P512_R1:
            return 512
        case PACEInfo.PARAM_ID_ECP_NIST_P521_R1:
            return 521
        default:
            throw NFCPassportReaderError.PACEError("Step2IM", "Unknown Integrated Mapping parameter size")
        }
    }
    
}

#endif
