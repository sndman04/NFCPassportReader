import Foundation
import OpenSSLCompat

/// Unauthenticated chip parameters are accepted only when equal to an ICAO standard
/// group already known to this reader (Part 11 §§9.2.2, 9.5). No primality inference,
/// attacker-selected generators, named-curve substitution or password trial is used.
final class PACEDomainParameterInfo: SecurityInfo {
    static let identifiers: Set<String> = ["0.4.0.127.0.7.2.2.4.1", "0.4.0.127.0.7.2.2.4.2",
        "0.4.0.127.0.7.2.2.4.3", "0.4.0.127.0.7.2.2.4.4", "0.4.0.127.0.7.2.2.4.6"]
    let oid: String
    let parameterId: Int?
    let standardParameterId: Int?
    private(set) var encodedParameters: [UInt8]

    init(oid: String, algorithm: SimpleASN1Node, identifier: SimpleASN1Node?) throws {
        guard algorithm.tag == 0x30, algorithm.children.count == 2,
              let algorithmOID = algorithm.children[0].objectIdentifier,
              identifier == nil || (identifier?.integerValue ?? -1) >= 32 else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        self.oid = oid
        parameterId = identifier?.integerValue
        encodedParameters = algorithm.encodedBytes
        let dh = oid == "0.4.0.127.0.7.2.2.4.1" || oid == "0.4.0.127.0.7.2.2.4.3"
        let parameters = algorithm.children[1]
        var known: Int?
        if algorithmOID == "0.4.0.127.0.7.1.2" {
            known = parameters.integerValue
        } else if algorithmOID == (dh ? "1.2.840.10046.2.1" : "1.2.840.10045.2.1") {
            // §9.5.2 excludes named/implicit EC parameters here.
            guard parameters.tag == 0x30 else { throw NFCPassportReaderError.InvalidASN1Structure }
            // OpenSSL may infer a missing/zero EC cofactor. Do not let normalization
            // erase a contradictory declaration: all Table 12 prime curves have h=1.
            let validCofactor = dh || parameters.children.count == 5
                || (parameters.children.count == 6 && parameters.children[5].value == [1]
                    && parameters.children[5].tag == 0x02)
            if validCofactor {
                let match = parameters.encodedBytes.withUnsafeBufferPointer {
                    NFCPRMatchKnownPACEParameters($0.baseAddress, $0.count, dh ? 0 : 1)
                }
                if match >= 0 { known = Int(match) }
            }
        }
        if let known, (dh ? (0...2).contains(known) : (8...18).contains(known)) {
            standardParameterId = known
        } else { standardParameterId = nil }
    }
    override func getObjectIdentifier() -> String { oid }
    override func getProtocolOIDString() -> String { "PACE domain parameters" }
    override func removeSensitiveDataForPrivacy() { encodedParameters.removeAll(keepingCapacity: false) }
}
