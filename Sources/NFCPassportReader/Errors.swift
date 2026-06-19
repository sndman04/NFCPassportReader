//
//  Errors.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 09/02/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

import Foundation

// MARK: TagError
@available(iOS 13, macOS 10.15, *)
public enum NFCPassportReaderError: Error {
    case ResponseError(String, UInt8, UInt8)
    case InvalidResponse(dataGroupId: DataGroupId, expectedTag: Int, actualTag: Int)
    case UnexpectedError
    case NFCNotSupported
    case NoConnectedTag
    case D087Malformed
    case InvalidResponseChecksum
    case MissingMandatoryFields
    case CannotDecodeASN1Length
    case InvalidASN1Value
    case InvalidASN1Structure
    case UnableToProtectAPDU
    case UnableToUnprotectAPDU
    case UnsupportedDataGroup
    case DataGroupNotRead
    case UnknownTag
    case UnknownImageFormat
    case NotImplemented
    case TagNotValid
    case ConnectionError
    case TimeOutError
    case UserCanceled
    case InvalidMRZKey
    case MoreThanOneTagFound
    case InvalidHashAlgorithmSpecified
    case UnsupportedCipherAlgorithm
    case UnsupportedMappingType
    case PACEError(String,String)
    case ChipAuthenticationFailed
    case InvalidDataPassed(String)
    case NotYetSupported(String)
    case Unknown(Error)

    var value: String {
        switch self {
            case .ResponseError(let errMsg, _, _): return errMsg
            case .InvalidResponse(let dataGroupId, let expected, let actual):
                return "InvalidResponse in \(dataGroupId.getName()). Expected: \(expected.hexString) Actual: \(actual.hexString)"
            case .UnexpectedError: return "UnexpectedError"
            case .NFCNotSupported: return "NFCNotSupported"
            case .NoConnectedTag: return "NoConnectedTag"
            case .D087Malformed: return "D087Malformed"
            case .InvalidResponseChecksum: return "InvalidResponseChecksum"
            case .MissingMandatoryFields: return "MissingMandatoryFields"
            case .CannotDecodeASN1Length: return "CannotDecodeASN1Length"
            case .InvalidASN1Value: return "InvalidASN1Value"
            case .InvalidASN1Structure: return "InvalidASN1Structure"
            case .UnableToProtectAPDU: return "UnableToProtectAPDU"
            case .UnableToUnprotectAPDU: return "UnableToUnprotectAPDU"
            case .UnsupportedDataGroup: return "UnsupportedDataGroup"
            case .DataGroupNotRead: return "DataGroupNotRead"
            case .UnknownTag: return "UnknownTag"
            case .UnknownImageFormat: return "UnknownImageFormat"
            case .NotImplemented: return "NotImplemented"
            case .TagNotValid: return "TagNotValid"
            case .ConnectionError: return "ConnectionError"
            case .TimeOutError: return "TimeOutError"
            case .UserCanceled: return "UserCanceled"
            case .InvalidMRZKey: return "InvalidMRZKey"
            case .MoreThanOneTagFound: return "MoreThanOneTagFound"
            case .InvalidHashAlgorithmSpecified: return "InvalidHashAlgorithmSpecified"
            case .UnsupportedCipherAlgorithm: return "UnsupportedCipherAlgorithm"
            case .UnsupportedMappingType: return "UnsupportedMappingType"
            case .PACEError(let step, let reason): return "PACEError (\(step)) - \(reason)"
            case .ChipAuthenticationFailed: return "ChipAuthenticationFailed"
            case .InvalidDataPassed(let reason) : return "Invalid data passed - \(reason)"
            case .NotYetSupported(let reason) : return "Not yet supported - \(reason)"
            case .Unknown(let error): return "Unknown error: \(error.localizedDescription)"
        }
    }

    public var safeDescription: String {
        switch self {
            case .ResponseError:
                return "Passport chip response error"
            case .InvalidResponse(let dataGroupId, _, _):
                return "Invalid response in \(dataGroupId.getName())"
            case .UnexpectedError: return "Unexpected read failure"
            case .NFCNotSupported: return "NFC not supported"
            case .NoConnectedTag: return "No connected NFC tag"
            case .D087Malformed: return "Malformed secure messaging response"
            case .InvalidResponseChecksum: return "Passport response verification failed"
            case .MissingMandatoryFields: return "Passport response is missing mandatory fields"
            case .CannotDecodeASN1Length: return "Unable to decode ASN.1 length"
            case .InvalidASN1Value: return "Invalid ASN.1 value"
            case .InvalidASN1Structure: return "Invalid ASN.1 structure"
            case .UnableToProtectAPDU: return "Unable to protect chip command"
            case .UnableToUnprotectAPDU: return "Unable to unprotect chip response"
            case .UnsupportedDataGroup: return "Unsupported data group"
            case .DataGroupNotRead: return "Data group was not read"
            case .UnknownTag: return "Unknown NFC tag"
            case .UnknownImageFormat: return "Unknown passport image format"
            case .NotImplemented: return "Passport feature is not implemented"
            case .TagNotValid: return "NFC tag is not valid"
            case .ConnectionError: return "NFC connection lost"
            case .TimeOutError: return "NFC session timed out"
            case .UserCanceled: return "NFC session canceled"
            case .InvalidMRZKey: return "Access key rejected"
            case .MoreThanOneTagFound: return "More than one NFC tag found"
            case .InvalidHashAlgorithmSpecified: return "Unsupported verification hash algorithm"
            case .UnsupportedCipherAlgorithm: return "Unsupported cipher algorithm"
            case .UnsupportedMappingType: return "Unsupported PACE mapping type"
            case .PACEError: return "PACE authentication failed"
            case .ChipAuthenticationFailed: return "Chip authentication failed"
            case .InvalidDataPassed: return "Invalid data passed"
            case .NotYetSupported: return "Passport feature is not supported"
            case .Unknown: return "Unexpected read failure"
        }
    }
}

@available(iOS 13, macOS 10.15, *)
extension NFCPassportReaderError: LocalizedError {
    public var errorDescription: String? {
        return NSLocalizedString(safeDescription, comment: "NFCPassportReaderError")
    }
}


// MARK: OpenSSLError
@available(iOS 13, macOS 10.15, *)
public enum OpenSSLError: Error {
    case UnableToGetX509CertificateFromPKCS7(String)
    case UnableToVerifyX509CertificateForSOD(String)
    case VerifyAndReturnSODEncapsulatedData(String)
    case UnableToReadECPublicKey(String)
    case UnableToExtractSignedDataFromPKCS7(String)
    case VerifySignedAttributes(String)
    case UnableToParseASN1(String)
    case UnableToDecryptRSASignature(String)
}

@available(iOS 13, macOS 10.15, *)
extension OpenSSLError: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .UnableToGetX509CertificateFromPKCS7:
                return NSLocalizedString("Unable to read the SOD PKCS7 certificate.", comment: "UnableToGetPKCS7CertificateForSOD")
            case .UnableToVerifyX509CertificateForSOD:
                return NSLocalizedString("Unable to verify the SOD X509 certificate.", comment: "UnableToVerifyX509CertificateForSOD")
            case .VerifyAndReturnSODEncapsulatedData:
                return NSLocalizedString("Unable to verify the SOD data group hashes.", comment: "UnableToGetSignedDataFromPKCS7")
            case .UnableToReadECPublicKey:
                return NSLocalizedString("Unable to read the ECDSA public key.", comment: "UnableToReadECPublicKey")
            case .UnableToExtractSignedDataFromPKCS7:
                return NSLocalizedString("Unable to extract signer data from PKCS7.", comment: "UnableToExtractSignedDataFromPKCS7")
            case .VerifySignedAttributes:
                return NSLocalizedString("Unable to verify the SOD signed attributes.", comment: "UnableToExtractSignedDataFromPKCS7")
            case .UnableToParseASN1:
                return NSLocalizedString("Unable to parse ASN.1 data.", comment: "UnableToParseASN1")
            case .UnableToDecryptRSASignature:
                return NSLocalizedString("Unable to decrypt RSA signature.", comment: "UnableToDecryptRSSignature")
        }
    }
}


// MARK: PassiveAuthenticationError
public enum PassiveAuthenticationError: Error {
    case UnableToParseSODHashes(String)
    case InvalidDataGroupHash(String)
    case SODMissing(String)
}


extension PassiveAuthenticationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .UnableToParseSODHashes:
                return NSLocalizedString("Unable to parse the SOD data group hashes.", comment: "UnableToParseSODHashes")
            case .InvalidDataGroupHash:
                return NSLocalizedString("Data group hash is missing or does not match.", comment: "InvalidDataGroupHash")
            case .SODMissing:
                return NSLocalizedString("Data group SOD is missing or was not read.", comment: "SODMissing")
                
        }
    }
}
