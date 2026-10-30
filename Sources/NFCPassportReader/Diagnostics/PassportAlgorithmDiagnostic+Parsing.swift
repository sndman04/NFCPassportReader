import Foundation

extension PassportAlgorithmDiagnostic {
    enum Role { case digest, signature, mask }

    static func read(_ node: SimpleASN1Node?, role: Role) -> Self? {
        guard let node else { return nil }
        guard node.tag == 0x30, (1...2).contains(node.children.count),
              let oid = node.children.first, oid.tag == 0x06, oid.value.count <= 32,
              oid.value.last.map({ $0 & 0x80 == 0 }) == true,
              let text = oid.objectIdentifier else {
            return .init(identifier: .unrecognized, parameterForm: .malformed, rsaPSS: nil)
        }
        let digestIDs: Set<PassportDiagnosticAlgorithm> = [.sha1, .sha224, .sha256, .sha384, .sha512]
        let signatureIDs: Set<PassportDiagnosticAlgorithm> = [.rsaEncryption, .rsaSHA1, .rsaSHA224, .rsaSHA256,
            .rsaSHA384, .rsaSHA512, .rsaPSS, .ecdsaSHA1, .ecdsaSHA224, .ecdsaSHA256, .ecdsaSHA384, .ecdsaSHA512]
        let allowed = role == .digest ? digestIDs : role == .signature ? signatureIDs : [.mgf1]
        let decoded = PassportDiagnosticAlgorithm(rawValue: text) ?? .unrecognized
        let identifier: PassportDiagnosticAlgorithm = allowed.contains(decoded) ? decoded : .unrecognized
        guard let parameters = node.children.dropFirst().first else {
            return .init(identifier: identifier, parameterForm: .absent, rsaPSS: nil)
        }
        if identifier == .rsaPSS {
            guard let pss = readPSS(parameters) else {
                return .init(identifier: identifier, parameterForm: .malformed, rsaPSS: nil)
            }
            return .init(identifier: identifier, parameterForm: .rsaPSS, rsaPSS: pss)
        }
        return .init(identifier: identifier,
                     parameterForm: parameters.tag == 0x05 && parameters.value.isEmpty ? .null : .unrecognized,
                     rsaPSS: nil)
    }

    private static func readPSS(_ node: SimpleASN1Node) -> PassportRSAPSSDiagnostic? {
        guard node.tag == 0x30, node.children.count <= 4 else { return nil }
        var seen = Set<Int>()
        var hash: PassportDiagnosticAlgorithm? = .sha1
        var mask: PassportDiagnosticAlgorithm? = .mgf1
        var maskHash: PassportDiagnosticAlgorithm? = .sha1
        var salt: Int? = 20
        var trailer: Int? = 1
        for field in node.children {
            guard (0xA0...0xA3).contains(field.tag), seen.insert(field.tag).inserted,
                  field.children.count == 1, let value = field.children.first else { return nil }
            switch field.tag {
            case 0xA0:
                guard let algorithm = read(value, role: .digest), algorithm.parameterForm != .malformed else { return nil }
                hash = algorithm.identifier
            case 0xA1:
                guard let algorithm = read(value, role: .mask), algorithm.parameterForm != .malformed else { return nil }
                mask = algorithm.identifier
                maskHash = mask == .mgf1 ? read(value.children.dropFirst().first, role: .digest)?.identifier : nil
            case 0xA2:
                guard let number = value.integerValue else { return nil }
                salt = (0...512).contains(number) ? number : nil
            case 0xA3:
                guard let number = value.integerValue else { return nil }
                trailer = number == 1 ? 1 : nil
            default: return nil
            }
        }
        return .init(hashAlgorithm: hash, maskGenerationAlgorithm: mask, maskGenerationHashAlgorithm: maskHash,
                     saltLength: salt, trailerField: trailer)
    }
}
