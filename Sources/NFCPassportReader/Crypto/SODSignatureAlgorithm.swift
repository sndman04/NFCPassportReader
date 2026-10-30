import Foundation

/// Security decisions use this validated representation, never diagnostic metadata.
/// RFC 4055 §3.1, RFC 4056 §§2.2–3, RFC 5652 §§5.3–5.6.
struct SODSignatureAlgorithm {
    enum Failure: Error { case malformed, unsupported }
    enum Padding { case rsaPKCS1, rsaPSS, ecdsa, dsa }
    let padding: Padding
    let digest: String
    var maskDigest: String?
    var saltLength: Int?

    static let digestOIDs = [
        "1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.4": "sha224",
        "2.16.840.1.101.3.4.2.1": "sha256", "2.16.840.1.101.3.4.2.2": "sha384",
        "2.16.840.1.101.3.4.2.3": "sha512"
    ]

    static func digest(_ node: SimpleASN1Node) throws -> String {
        guard node.tag == 0x30, (1...2).contains(node.children.count),
              let oid = node.children[0].objectIdentifier,
              node.children.count == 1 || (node.children[1].tag == 0x05 && node.children[1].value.isEmpty) else {
            throw malformed()
        }
        guard let name = digestOIDs[oid] else { throw unsupported() }
        return name
    }

    init(_ node: SimpleASN1Node, contentDigest: String) throws {
        guard node.tag == 0x30, (1...2).contains(node.children.count),
              let oid = node.children[0].objectIdentifier else { throw Self.malformed() }
        if oid == "1.2.840.113549.1.1.10" {
            // Parameters are mandatory for a signature; omitted members have ASN.1 defaults.
            guard node.children.count == 2, node.children[1].tag == 0x30 else { throw Self.malformed() }
            var hash = "sha1", mgfHash = "sha1", salt = 20
            var previous = 0x9F
            for field in node.children[1].children {
                guard (0xA0...0xA3).contains(field.tag), field.tag > previous,
                      field.children.count == 1 else { throw Self.malformed() }
                previous = field.tag
                let value = field.children[0]
                switch field.tag {
                case 0xA0: hash = try Self.digest(value)
                case 0xA1:
                    guard value.tag == 0x30, value.children.count == 2,
                          value.children[0].objectIdentifier == "1.2.840.113549.1.1.8" else { throw Self.unsupported() }
                    mgfHash = try Self.digest(value.children[1])
                case 0xA2:
                    guard let length = value.integerValue, length <= 65_536,
                          value.value.count == 1 || value.value.first != 0 || value.value[1] & 0x80 != 0 else {
                        throw Self.malformed()
                    }
                    salt = length
                default:
                    guard value.tag == 0x02, value.value == [1] else { throw Self.unsupported() }
                }
            }
            padding = .rsaPSS
            digest = hash
            maskDigest = mgfHash
            saltLength = salt
            return
        }
        let rsa = ["1.2.840.113549.1.1.5": "sha1", "1.2.840.113549.1.1.14": "sha224",
                   "1.2.840.113549.1.1.11": "sha256", "1.2.840.113549.1.1.12": "sha384",
                   "1.2.840.113549.1.1.13": "sha512"]
        let ec = ["1.2.840.10045.4.1": "sha1", "1.2.840.10045.4.3.1": "sha224",
                  "1.2.840.10045.4.3.2": "sha256", "1.2.840.10045.4.3.3": "sha384",
                  "1.2.840.10045.4.3.4": "sha512"]
        let dsa = ["1.2.840.10040.4.3": "sha1", "2.16.840.1.101.3.4.3.1": "sha224",
                   "2.16.840.1.101.3.4.3.2": "sha256", "2.16.840.1.101.3.4.3.3": "sha384",
                   "2.16.840.1.101.3.4.3.4": "sha512"]
        if let hash = rsa[oid] ?? (oid == "1.2.840.113549.1.1.1" ? contentDigest : nil) {
            guard node.children.count == 1 || (node.children[1].tag == 0x05 && node.children[1].value.isEmpty),
                  hash == contentDigest else { throw Self.malformed() }
            padding = .rsaPKCS1
            digest = hash
        } else if let hash = ec[oid] {
            guard node.children.count == 1, hash == contentDigest else { throw Self.malformed() }
            padding = .ecdsa
            digest = hash
        } else if let hash = dsa[oid] {
            guard node.children.count == 1, hash == contentDigest else { throw Self.malformed() }
            padding = .dsa
            digest = hash
        } else { throw Self.unsupported() }
    }

    static func malformed() -> Failure { .malformed }
    static func unsupported() -> Failure { .unsupported }
}
