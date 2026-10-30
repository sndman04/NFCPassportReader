import Foundation
import OpenSSLCompat

/// Offline CRL checking. Callers supply a local, maintained bundle; the reader never
/// follows distribution-point URLs or sends certificate/document identifiers to a server.
enum CertificateRevocation {
    static func check(_ data: Data, signer: X509Wrapper, issuer: X509Wrapper) -> PassportDiagnosticCheck {
        let result = data.withUnsafeBytes {
            NFCPRCheckRevocation($0.baseAddress?.assumingMemoryBound(to: UInt8.self), data.count, signer.cert, issuer.cert)
        }
        if result == 1 { return .passed }
        let reason: PassportDiagnosticReason
        switch result {
        case 2: reason = .certificateRevoked
        case 3: reason = .revocationListUnavailable
        case 5: reason = .revocationListExpired
        case 6: reason = .revocationListNotYetValid
        default: reason = .revocationListInvalid
        }
        return .failed(.init(subsystem: .trust, operation: .checkRevocation, stage: .passiveAuthentication, reason: reason))
    }
    static func load(_ url: URL) throws -> Data {
        guard url.isFileURL else { throw OpenSSLError.UnableToVerifyX509CertificateForSOD("A local CRL bundle is required") }
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        guard !data.isEmpty, data.count <= 16 * 1024 * 1024 else {
            throw OpenSSLError.UnableToVerifyX509CertificateForSOD("Invalid CRL bundle size")
        }
        return data
    }
}
