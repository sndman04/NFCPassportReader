import Foundation
#if !os(macOS)
import CoreNFC
#endif

/// Internal accumulator; all published forms are immutable values with fixed vocabulary.
struct PassportDiagnosticEvidence {
    var stages: [PassportSODParsingStage: PassportDiagnosticCheck] = [:]
    var version: PassportSODVersion?
    var ldsVersionInfo: PassportDiagnosticPresence = .unavailable
    var contentDigest: PassportAlgorithmDiagnostic?
    var signerDigest: PassportAlgorithmDiagnostic?
    var signature: PassportAlgorithmDiagnostic?
    var groupDigest: PassportAlgorithmDiagnostic?
    var manual = PassportDiagnosticCheck()
    var cms = PassportDiagnosticCheck()
    var preferred: PassportSODVerifier?
    var fallback = false
    var winner: PassportSODVerifier?
    var signatureCheck = PassportDiagnosticCheck()
    var hashes = PassportDiagnosticCheck()
    var trust = PassportDiagnosticCheck()
    var revocation = PassportDiagnosticCheck()
    var hashCoverageAvailable = false
    var observedHashGroups = Set<DataGroupId>()

    mutating func captureLDSMetadata(_ root: SimpleASN1Node) {
        guard root.tag == 0x30 else { return }
        if let number = root.children.first?.integerValue {
            version = number == 0 ? .v0 : number == 1 ? .v1 : .other
        }
        ldsVersionInfo = root.children.count <= 3 ? .absent
            : root.children[3].tag == 0x30 ? .present : .unavailable
        groupDigest = PassportAlgorithmDiagnostic.read(root.children.dropFirst().first, role: .digest)
    }

    var sod: PassportSODDiagnostic {
        PassportSODDiagnostic(
            stages: PassportSODParsingStage.allCases.map { .init(stage: $0, check: stages[$0] ?? .init()) },
            version: version, ldsVersionInfo: ldsVersionInfo, contentDigestAlgorithm: contentDigest,
            signerDigestAlgorithm: signerDigest, signatureAlgorithm: signature, dataGroupDigestAlgorithm: groupDigest,
            manualVerifier: manual, cmsVerifier: cms, preferredVerifier: preferred,
            fallbackAttempted: fallback, successfulVerifier: winner)
    }
}

extension PassportDiagnosticFailure {
    static func capture(_ error: Error, stage: PassportReaderScanStage,
                        operation: PassportDiagnosticOperation = .scan) -> Self {
        #if !os(macOS)
        if let nfc = error as? NFCReaderError {
            let reason: PassportDiagnosticReason
            switch nfc.code {
            case .readerSessionInvalidationErrorUserCanceled: reason = .canceled
            case .readerSessionInvalidationErrorSessionTimeout: reason = .timeout
            case .readerTransceiveErrorTagConnectionLost: reason = .connectionLost
            default: reason = .unknownFailure
            }
            return .init(subsystem: .coreNFC, operation: operation, stage: stage,
                         reason: reason, coreNFCCode: nfc.code.rawValue)
        }
        #endif
        if error is CancellationError {
            return .init(subsystem: .reader, operation: operation, stage: stage, reason: .canceled)
        }
        var subsystem: PassportDiagnosticSubsystem = .reader
        var reason: PassportDiagnosticReason = .unknownFailure
        var parser: PassportParserDiagnostic?
        var word: UInt16?
        if let error = error as? NFCPassportReaderError {
            switch error {
            case .ResponseError(_, let sw1, let sw2):
                subsystem = .transport; reason = .responseStatus; word = UInt16(sw1) << 8 | UInt16(sw2)
            case .InvalidResponse(_, let expected, let actual):
                subsystem = .parser; reason = .malformedStructure
                parser = .init(expectedTag: expected, actualTag: actual)
            case .CannotDecodeASN1Length, .InvalidASN1Structure, .InvalidASN1Value, .MissingMandatoryFields, .UnknownTag:
                subsystem = .parser; reason = .malformedStructure
            case .InvalidResponseChecksum, .D087Malformed, .UnableToProtectAPDU, .UnableToUnprotectAPDU:
                subsystem = .cryptography; reason = .secureMessagingIntegrity
            case .InvalidMRZKey: subsystem = .authentication; reason = .accessRejected
            case .PACEError, .ActiveAuthenticationFailed, .ChipAuthenticationFailed:
                subsystem = .authentication; reason = .cryptoFailure
            case .InvalidHashAlgorithmSpecified, .UnsupportedCipherAlgorithm, .UnsupportedMappingType:
                subsystem = .cryptography; reason = .unsupportedAlgorithm
            case .UserCanceled: reason = .canceled
            case .TimeOutError: reason = .timeout
            case .ConnectionError, .NoConnectedTag: subsystem = .transport; reason = .connectionLost
            case .NFCNotSupported: subsystem = .coreNFC; reason = .nfcUnavailable
            case .SecurityPolicyViolation: subsystem = .policy; reason = .policyRejected
            case .InvalidDataPassed: reason = .invalidInput
            case .DataGroupNotRead: reason = .missingDataGroup
            case .UnsupportedDataGroup, .NotImplemented, .NotYetSupported, .UnknownImageFormat: reason = .notSupported
            default: break // Associated strings and nested errors are deliberately not inspected.
            }
        } else if let error = error as? OpenSSLError {
            subsystem = .cryptography
            switch error {
            case .UnableToGetX509CertificateFromPKCS7: reason = .certificateUnavailable
            case .UnableToVerifyX509CertificateForSOD: subsystem = .trust; reason = .chainInvalid
            case .UnableToExtractSignedDataFromPKCS7, .UnableToParseASN1: subsystem = .parser; reason = .malformedStructure
            case .VerifyAndReturnSODEncapsulatedData, .VerifySignedAttributes: reason = .signatureInvalid
            default: reason = .cryptoFailure
            }
        } else if let error = error as? PassiveAuthenticationError {
            switch error {
            case .SODMissing: reason = .missingSOD
            case .UnableToParseSODHashes: subsystem = .parser; reason = .malformedStructure
            case .InvalidDataGroupHash: reason = .hashMismatch
            case .NoDataGroupHashesCompared: reason = .noHashesCompared
            }
        }
        return .init(subsystem: subsystem, operation: operation, stage: stage, reason: reason,
                     statusWord: word, parser: parser)
    }
}

extension PassportDiagnosticCheck {
    static func failed(_ failure: PassportDiagnosticFailure) -> Self {
        .init(failure.reason == .unsupportedAlgorithm || failure.reason == .unsupportedVersion ? .unsupported : .failed,
              failure.reason, attempted: true, failure: failure)
    }

}
