import XCTest
import OpenSSL
import OpenSSLCompat
@testable import NFCPassportReader

final class CryptoBoundaryRegressionTests: XCTestCase {
    func testAESCMACKnownAnswerAndParameterLifetime() {
        // RFC 4493 public test vector, not document/session material.
        let key = hexRepToBin("2b7e151628aed2a6abf7158809cf4f3c")
        let expected = hexRepToBin("bb1d6929e95937287fa37d129b756746")
        for _ in 0..<20 {
            XCTAssertTrue(OpenSSLUtils.generateAESCMAC(key: key, message: []) == expected, "AES-CMAC known-answer mismatch")
        }
        XCTAssertTrue(OpenSSLUtils.generateAESCMAC(key: [], message: []).isEmpty)
    }

    func testDHAndECWireKeysRetainParametersAndDeriveMatchingSecrets() throws {
        for isDH in [true, false] {
            let first = try isDH ? OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 1) : OpenSSLUtils.generateECKeyPair(curveNID: NID_X9_62_prime256v1)
            defer { EVP_PKEY_free(first) }
            try assertKeyAgreement(parameters: first)
        }
    }

    func testMappedDHAndECDHWireKeysRetainMappedParameters() throws {
        for isDH in [true, false] {
            let mapping = try isDH ? OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 1) : OpenSSLUtils.generateECKeyPair(curveNID: NID_X9_62_prime256v1)
            defer { EVP_PKEY_free(mapping) }
            let other = try OpenSSLUtils.generateKeyPair(fromParameters: mapping)
            defer { EVP_PKEY_free(other) }
            let wire = try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: other))
            let nonce = try XCTUnwrap(BN_new())
            defer { BN_clear_free(nonce) }
            XCTAssertEqual(BN_set_word(nonce, 42), 1)
            let mapped = try XCTUnwrap(wire.withUnsafeBufferPointer {
                isDH ? NFCPRCreateDHMappedParameters(mapping, $0.baseAddress, $0.count, nonce)
                    : NFCPRCreateECDHMappedParameters(mapping, $0.baseAddress, $0.count, nonce)
            })
            defer { EVP_PKEY_free(mapped) }
            try assertKeyAgreement(parameters: mapped)
        }
    }

    func testMalformedAndOutOfRangePeerKeysAreRejected() throws {
        let dh = try OpenSSLUtils.generateDHXKeyPair(rfc5114Group: 1)
        defer { EVP_PKEY_free(dh) }
        XCTAssertNil(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: [0], params: dh))
        XCTAssertNil(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: [1], params: dh))
        let ec = try OpenSSLUtils.generateECKeyPair(curveNID: NID_X9_62_prime256v1)
        defer { EVP_PKEY_free(ec) }
        XCTAssertNil(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: [0], params: ec))
        XCTAssertNil(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: [4, 1, 2], params: ec))
    }

    private func assertKeyAgreement(parameters: OpaquePointer) throws {
        let alice = try OpenSSLUtils.generateKeyPair(fromParameters: parameters)
        let bob = try OpenSSLUtils.generateKeyPair(fromParameters: parameters)
        defer { EVP_PKEY_free(alice); EVP_PKEY_free(bob) }
        let aliceWire = try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: alice))
        let bobWire = try XCTUnwrap(OpenSSLUtils.getPublicKeyData(from: bob))
        let alicePublic = try XCTUnwrap(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: aliceWire, params: bob))
        let bobPublic = try XCTUnwrap(OpenSSLUtils.decodePublicKeyFromBytes(pubKeyData: bobWire, params: alice))
        defer { EVP_PKEY_free(alicePublic); EVP_PKEY_free(bobPublic) }
        XCTAssertEqual(EVP_PKEY_parameters_eq(alicePublic, parameters), 1)
        XCTAssertEqual(EVP_PKEY_parameters_eq(bobPublic, parameters), 1)
        let first = try OpenSSLUtils.computeSharedSecret(privateKeyPair: alice, publicKey: bobPublic)
        let second = try OpenSSLUtils.computeSharedSecret(privateKeyPair: bob, publicKey: alicePublic)
        XCTAssertFalse(first.isEmpty)
        XCTAssertTrue(first == second, "Synthetic shared secrets must agree")
    }
}
