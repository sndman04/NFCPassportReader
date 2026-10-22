import Foundation

#if !os(macOS)
@preconcurrency import CoreNFC

/// Internal seam: production and scripted tests use the same APDU construction,
/// status handling, secure messaging, and authentication implementations.
@available(iOS 15, *)
@MainActor
protocol PassportTagTransport: Sendable {
    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8)
}

@available(iOS 15, *)
final class CoreNFCPassportTagTransport: PassportTagTransport {
    private let connection: CoreNFCConnection
    init(tag: NFCISO7816Tag) { connection = CoreNFCConnection(tag: tag) }

    func sendCommand(apdu: NFCISO7816APDU) async throws -> (Data, UInt8, UInt8) {
        try await connection.send(command: CoreNFCCommand(apdu))
    }
}

/// NFCISO7816APDU exposes only readonly fields (including a copied NSData).
/// Bridge that immutable SDK object without reconstructing its short/extended
/// length encoding. Never include this value in diagnostics.
@available(iOS 15, *)
private struct CoreNFCCommand: @unchecked Sendable {
    let apdu: NFCISO7816APDU
    init(_ apdu: NFCISO7816APDU) { self.apdu = apdu }
}

/// CoreNFC's tag protocol is not Sendable-annotated. Only its transport call is
/// unchecked; TagReader serializes calls and revokes access on the main actor.
@available(iOS 15, *)
private final class CoreNFCConnection: @unchecked Sendable {
    private let tag: NFCISO7816Tag
    init(tag: NFCISO7816Tag) { self.tag = tag }

    func send(command: CoreNFCCommand) async throws -> (Data, UInt8, UInt8) {
        return try await tag.sendCommand(apdu: command.apdu)
    }
}
#endif
