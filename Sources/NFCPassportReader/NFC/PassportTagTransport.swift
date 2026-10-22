import Foundation

#if !os(macOS)
@preconcurrency import CoreNFC

/// Internal seam: production and scripted tests use the same APDU construction,
/// status handling, secure messaging, and authentication implementations.
@available(iOS 15, *)
protocol PassportTagTransport: Sendable {
    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8)
}

@available(iOS 15, *)
final class CoreNFCPassportTagTransport: PassportTagTransport, @unchecked Sendable {
    // CoreNFC's tag protocol is not Sendable-annotated. Access remains
    // serialized by the reader's scan task, as with TagReader.
    private let tag: NFCISO7816Tag
    init(tag: NFCISO7816Tag) { self.tag = tag }

    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        try await tag.sendCommand(apdu: apdu)
    }
}
#endif
