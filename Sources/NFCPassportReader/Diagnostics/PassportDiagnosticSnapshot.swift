import Foundation

/// Outcome of an individual diagnostic check. Only `succeeded` means a check passed.
public enum PassportDiagnosticStatus: String, Sendable, Encodable {
    case notAttempted, unavailable, skipped, unsupported, inProgress, succeeded, failed
}

/// Fixed vocabulary; no underlying error descriptions or document strings are retained.
public enum PassportDiagnosticReason: String, Sendable, Encodable {
    case none, notRequested, missingSOD, missingMasterList, missingDataGroup, prerequisiteFailed
    case notSupported, skippedByConfiguration, malformedStructure, unsupportedVersion, unsupportedAlgorithm
    case signatureInvalid, signedContentDigestMismatch, hashMismatch, hashNotCovered, noHashesCompared
    case certificateUnavailable, trustStoreUnavailable, issuerNotFound, certificateExpired, certificateNotYetValid
    case certificateSignatureInvalid, certificateRevoked, invalidCertificatePurpose, chainInvalid
    case cryptoFailure, resourceFailure, accessRejected, responseStatus, secureMessagingIntegrity
    case canceled, timeout, connectionLost, nfcUnavailable, invalidInput, policyRejected, unknownFailure
}

public enum PassportDiagnosticSubsystem: String, Sendable, Encodable {
    case reader, coreNFC, transport, parser, cryptography, trust, authentication, policy
}

public enum PassportDiagnosticOperation: String, Sendable, Encodable {
    case scan, connect, invalidateSession, sendCommand, parseDataGroup, parseSOD
    case manualVerification, cmsVerification, compareHashes, validateChain, activeAuthentication, chipAuthentication
}

/// Numeric structure only. Values outside the documented bounds/known tag set are omitted.
public struct PassportParserDiagnostic: Sendable, Equatable, Encodable {
    public let expectedTag: Int?
    public let actualTag: Int?
    public let expectedLength: Int?
    public let actualLength: Int?
    public let offset: Int?

    init(expectedTag: Int? = nil, actualTag: Int? = nil, expectedLength: Int? = nil,
         actualLength: Int? = nil, offset: Int? = nil) {
        let tags: Set<Int> = [0x02, 0x04, 0x05, 0x06, 0x13, 0x30, 0x31, 0x60, 0x61,
                             0x63, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C,
                             0x6D, 0x6E, 0x6F, 0x70, 0x75, 0x76, 0x77, 0xA0, 0xA1, 0xA2, 0xA3]
        self.expectedTag = expectedTag.flatMap { tags.contains($0) ? $0 : nil }
        self.actualTag = actualTag.flatMap { tags.contains($0) ? $0 : nil }
        self.expectedLength = Self.bounded(expectedLength)
        self.actualLength = Self.bounded(actualLength)
        self.offset = Self.bounded(offset)
    }

    private static func bounded(_ value: Int?) -> Int? {
        value.flatMap { (0...16_777_216).contains($0) ? $0 : nil }
    }
}

/// Safe context captured at the failure site, before error translation.
public struct PassportDiagnosticFailure: Sendable, Equatable, Encodable {
    public let subsystem: PassportDiagnosticSubsystem
    public let operation: PassportDiagnosticOperation
    public let stage: PassportReaderScanStage
    public let reason: PassportDiagnosticReason
    public let coreNFCCode: Int?
    /// SW1 << 8 | SW2; only a failing response status, never a command or transcript.
    public let statusWord: UInt16?
    public let parser: PassportParserDiagnostic?
    /// X509 verification code, not an OpenSSL error string/queue or certificate metadata.
    public let certificateValidationCode: Int?

    init(subsystem: PassportDiagnosticSubsystem, operation: PassportDiagnosticOperation,
         stage: PassportReaderScanStage = .unknown, reason: PassportDiagnosticReason,
         coreNFCCode: Int? = nil, statusWord: UInt16? = nil, parser: PassportParserDiagnostic? = nil,
         certificateValidationCode: Int? = nil) {
        self.subsystem = subsystem
        self.operation = operation
        self.stage = stage
        self.reason = reason
        self.coreNFCCode = coreNFCCode
        self.statusWord = statusWord
        self.parser = parser
        self.certificateValidationCode = certificateValidationCode
    }
}

public struct PassportDiagnosticCheck: Sendable, Equatable, Encodable {
    public let attempted: Bool
    public let status: PassportDiagnosticStatus
    public let reason: PassportDiagnosticReason
    public let failure: PassportDiagnosticFailure?

    init(_ status: PassportDiagnosticStatus = .notAttempted, _ reason: PassportDiagnosticReason = .notRequested,
         attempted: Bool = false, failure: PassportDiagnosticFailure? = nil) {
        self.attempted = attempted
        self.status = status
        self.reason = reason
        self.failure = failure
    }

    static let passed = Self(.succeeded, .none, attempted: true)
}

/// Fixed OID allowlist. Unknown identifiers are represented by `unrecognized`, never their input text.
public enum PassportDiagnosticAlgorithm: String, Sendable, Encodable {
    case sha1 = "1.3.14.3.2.26"
    case sha224 = "2.16.840.1.101.3.4.2.4"
    case sha256 = "2.16.840.1.101.3.4.2.1"
    case sha384 = "2.16.840.1.101.3.4.2.2"
    case sha512 = "2.16.840.1.101.3.4.2.3"
    case rsaEncryption = "1.2.840.113549.1.1.1"
    case rsaSHA1 = "1.2.840.113549.1.1.5"
    case rsaSHA224 = "1.2.840.113549.1.1.14"
    case rsaSHA256 = "1.2.840.113549.1.1.11"
    case rsaSHA384 = "1.2.840.113549.1.1.12"
    case rsaSHA512 = "1.2.840.113549.1.1.13"
    case rsaPSS = "1.2.840.113549.1.1.10"
    case mgf1 = "1.2.840.113549.1.1.8"
    case ecdsaSHA1 = "1.2.840.10045.4.1"
    case ecdsaSHA224 = "1.2.840.10045.4.3.1"
    case ecdsaSHA256 = "1.2.840.10045.4.3.2"
    case ecdsaSHA384 = "1.2.840.10045.4.3.3"
    case ecdsaSHA512 = "1.2.840.10045.4.3.4"
    case unrecognized
}

public enum PassportAlgorithmParameterForm: String, Sendable, Encodable {
    case absent, null, rsaPSS, unrecognized, malformed
}

/// Declared effective PSS parameters (ASN.1 defaults applied), not a claim they were used by a verifier.
public struct PassportRSAPSSDiagnostic: Sendable, Equatable, Encodable {
    public let hashAlgorithm: PassportDiagnosticAlgorithm?
    public let maskGenerationAlgorithm: PassportDiagnosticAlgorithm?
    public let maskGenerationHashAlgorithm: PassportDiagnosticAlgorithm?
    public let saltLength: Int?
    public let trailerField: Int?
}

public struct PassportAlgorithmDiagnostic: Sendable, Equatable, Encodable {
    public let identifier: PassportDiagnosticAlgorithm
    public let parameterForm: PassportAlgorithmParameterForm
    public let rsaPSS: PassportRSAPSSDiagnostic?
}

public enum PassportSODParsingStage: String, Sendable, Encodable, CaseIterable {
    case envelope, signedData, signerInfo, encapsulatedContent, ldsSecurityObject, dataGroupHashes
}

public struct PassportSODStageDiagnostic: Sendable, Equatable, Encodable {
    public let stage: PassportSODParsingStage
    public let check: PassportDiagnosticCheck
}

public enum PassportSODVersion: String, Sendable, Encodable { case v0, v1, other }
public enum PassportDiagnosticPresence: String, Sendable, Encodable { case unavailable, absent, present }
public enum PassportSODVerifier: String, Sendable, Encodable { case manual, cms }

public struct PassportSODDiagnostic: Sendable, Equatable, Encodable {
    public let stages: [PassportSODStageDiagnostic]
    public let version: PassportSODVersion?
    public let ldsVersionInfo: PassportDiagnosticPresence
    public let contentDigestAlgorithm: PassportAlgorithmDiagnostic?
    public let signerDigestAlgorithm: PassportAlgorithmDiagnostic?
    public let signatureAlgorithm: PassportAlgorithmDiagnostic?
    public let dataGroupDigestAlgorithm: PassportAlgorithmDiagnostic?
    public let manualVerifier: PassportDiagnosticCheck
    public let cmsVerifier: PassportDiagnosticCheck
    public let preferredVerifier: PassportSODVerifier?
    public let fallbackAttempted: Bool
    public let successfulVerifier: PassportSODVerifier?
}

public struct PassportVerificationDiagnostics: Sendable, Equatable, Encodable {
    public let sodSignature: PassportDiagnosticCheck
    public let dataGroupHashes: PassportDiagnosticCheck
    /// Same chain validation as countrySignerTrust; not an independent certificate check.
    public let documentSignerTrust: PassportDiagnosticCheck
    public let countrySignerTrust: PassportDiagnosticCheck
    public let activeAuthentication: PassportDiagnosticCheck
    public let chipAuthentication: PassportDiagnosticCheck
    public let revocation: PassportDiagnosticCheck
}

public enum PassportHashCoverage: String, Sendable, Encodable { case unavailable, covered, notCovered }
public struct PassportDataGroupHashDiagnostic: Sendable, Equatable, Encodable {
    public let dataGroup: DataGroupId
    public let wasRead: Bool
    public let coverage: PassportHashCoverage
    public let comparison: PassportDiagnosticCheck
}

public enum PassportDiagnosticOutcome: String, Sendable, Encodable { case succeeded, failed, canceled, timedOut }

/// Immutable, bounded diagnostic record, captured before scrubbing. Contains no passport content.
/// Safe to encode separately from the identity result. Schema and availability rules: DIAGNOSTICS.md.
/// Publication is MainActor-isolated; the resulting value is Sendable. No automatic persistence occurs.
public struct PassportDiagnosticSnapshot: Sendable, Equatable, Encodable {
    public let schemaVersion: Int
    /// Reader-local generation, not a document identifier. Resets for a new reader instance.
    public let attemptID: UInt64
    public let outcome: PassportDiagnosticOutcome
    public let terminalFailure: PassportDiagnosticFailure?
    public let verification: PassportVerificationDiagnostics
    public let sod: PassportSODDiagnostic
    public let dataGroups: [PassportDataGroupHashDiagnostic]
    /// First 32 unique failure contexts in observation order. Terminal failure is always separate.
    public let failures: [PassportDiagnosticFailure]
    public let droppedFailureCount: Int
}

/// Delivered once per completed attempt, independent of console logging configuration.
public typealias PassportDiagnosticHandler = @MainActor @Sendable (PassportDiagnosticSnapshot) -> Void

extension DataGroupId: Encodable {}
