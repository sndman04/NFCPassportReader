import Foundation
import XCTest
import OpenSSL
import PassportTestSupport
@testable import NFCPassportReader

// Only public standards examples or generated test material belong in this bundle.
// Never include fixture values in assertion messages or XCTest attachments.
struct ICAOVector {
    let fields: [String: String]
    init(_ name: String) throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "icao9303", withExtension: "json", subdirectory: "Fixtures"))
        let all = try JSONDecoder().decode([String: [String: String]].self, from: Data(contentsOf: url))
        fields = try XCTUnwrap(all[name], "Missing named standards fixture")
    }
    func bytes(_ name: String) throws -> [UInt8] {
        let value = try XCTUnwrap(fields[name], "Missing standards fixture field")
        let bytes = hexRepToBin(value)
        guard bytes.count * 2 == value.count else { throw VectorError.invalidFixture }
        return bytes
    }
    var isDH: Bool { fields["kind"] == "DH" }
    func parameters() throws -> OpaquePointer {
        try isDH ? OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 1) : OpenSSLUtils.generateECKeyPair(curveNID: NID_brainpoolP256r1)
    }
}

enum VectorError: Error { case invalidFixture }

// Import only published test key pairs; validate their private/public consistency.
func importVectorKey(parameters: OpaquePointer, privateBytes: [UInt8], publicBytes: [UInt8], isDH: Bool) throws -> OpaquePointer {
    try privateBytes.withUnsafeBufferPointer { secret in
        try publicBytes.withUnsafeBufferPointer { pub in
            try XCTUnwrap(NFCPRTestImportKey(parameters, secret.baseAddress, secret.count, pub.baseAddress, pub.count, isDH ? 1 : 0), "Invalid published key pair")
        }
    }
}
