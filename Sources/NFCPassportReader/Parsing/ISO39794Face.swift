import Foundation

/// ICAO TR ISO/IEC 39794-5 Application Profile (August 2023), §§2–5 and Annex A.
/// Schema attribution and license: THIRD_PARTY_NOTICES.md. Unknown extension fields
/// are skipped at their declared boundary, as §3.1 requires; image bytes are never scanned.
struct ISO39794Face {
    let generation: Int
    let year: Int
    let format: Int
    let width: Int
    let height: Int
    let image: [UInt8]

    init(_ encoded: [UInt8]) throws {
        let wrapper = try SimpleASN1Node.parse(encoded)
        guard wrapper.tag == 0xA1, wrapper.children.count == 1,
              wrapper.children[0].tag == 0x65, Self.canonicalLengths(wrapper) else { throw Self.invalid }
        let face = try Self.fields(wrapper.children[0])
        let version = try Self.fields(Self.required(face, 0, tag: 0xA0))
        generation = try Self.number(Self.required(version, 0, tag: 0x80), range: 3...65535)
        year = try Self.number(Self.required(version, 1, tag: 0x81), range: 2019...9999)
        let representations = try Self.required(face, 1, tag: 0xA1)
        // The ICAO application profile permits one representation per BIT. Multiple
        // facial images use multiple BITs, which DataGroup2 parses independently.
        guard representations.children.count == 1, representations.children[0].tag == 0x30 else { throw Self.invalid }
        let representation = try Self.fields(representations.children[0])
        try Self.nonnegative(Self.required(representation, 0, tag: 0x80))
        let choice = try Self.required(representation, 1, tag: 0xA1)
        guard choice.children.count == 1, choice.children[0].tag == 0xA0,
              choice.children[0].children.count == 1,
              choice.children[0].children[0].tag == 0xA0 else { throw NFCPassportReaderError.UnknownImageFormat }
        let block = try Self.fields(choice.children[0].children[0])
        image = try Self.required(block, 0, tag: 0x80).value
        guard !image.isEmpty, image.count <= 10 * 1024 * 1024 else { throw NFCPassportReaderError.UnknownImageFormat }
        let information = try Self.fields(Self.required(block, 1, tag: 0xA1))
        let formatChoice = try Self.required(information, 0, tag: 0xA0)
        guard formatChoice.children.count == 1, formatChoice.children[0].tag == 0x80 else {
            throw NFCPassportReaderError.UnknownImageFormat
        }
        format = try Self.number(formatChoice.children[0], range: 2...4)
        let jpeg = image.starts(with: [0xFF, 0xD8, 0xFF])
        let jp2 = image.starts(with: [0, 0, 0, 12, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A])
            || image.starts(with: [0xFF, 0x4F, 0xFF, 0x51])
        guard format == 2 ? jpeg : jp2 else { throw NFCPassportReaderError.UnknownImageFormat }
        if let size = information[7] {
            guard size.tag == 0xA7 else { throw Self.invalid }
            let dimensions = try Self.fields(size)
            guard dimensions.count == 2 else { throw Self.invalid }
            width = try Self.number(Self.required(dimensions, 0, tag: 0x80), range: 0...20_000)
            height = try Self.number(Self.required(dimensions, 1, tag: 0x81), range: 0...20_000)
        } else { width = 0; height = 0 }
        if let kind = information[1] {
            // Profile restricts this extensible enumeration to its MRTD fallback.
            guard kind.tag == 0xA1, kind.children.count == 1, kind.children[0].tag == 0xA1 else { throw Self.invalid }
            let extensionFields = try Self.fields(kind.children[0])
            _ = try Self.number(Self.required(extensionFields, 0, tag: 0x80), range: 0...0)
        }
        // Validate the types of known optional blocks without retaining personal metadata.
        try Self.checkTypes(representation, [2: 0xA2, 3: 0xA3, 4: 0xA4, 5: 0x85, 6: 0x86, 7: 0xA7, 8: 0xA8, 9: 0xA9])
        for index in [5, 6] { if let number = representation[index] { try Self.nonnegative(number) } }
        try Self.checkTypes(block, [2: 0xA2])
        try Self.checkTypes(information, [2: 0xA2, 3: 0xA3, 4: 0x84, 5: 0x85, 6: 0x86, 8: 0xA8, 9: 0xA9, 10: 0xAA])
        for (index, limit) in [(4, 50_000), (5, 2000), (6, 2000)] {
            if let number = information[index] { _ = try Self.number(number, range: 0...limit) }
        }
    }

    private static var invalid: NFCPassportReaderError { .InvalidASN1Structure }

    /// Context-specific fields in an extensible SEQUENCE must be unique and ordered.
    private static func fields(_ node: SimpleASN1Node) throws -> [Int: SimpleASN1Node] {
        var result: [Int: SimpleASN1Node] = [:]
        var previous = -1
        for field in node.children {
            let bytes = field.encodedBytes
            guard let first = bytes.first, first & 0xC0 == 0x80 else { throw invalid }
            var tag = Int(first & 0x1F)
            if tag == 31 {
                tag = 0
                for byte in bytes.dropFirst() {
                    guard tag <= (Int.max >> 7) else { throw invalid }
                    tag = (tag << 7) | Int(byte & 0x7F)
                    if byte & 0x80 == 0 { break }
                }
            }
            guard tag > previous else { throw invalid }
            previous = tag
            result[tag] = field
        }
        return result
    }
    private static func required(_ fields: [Int: SimpleASN1Node], _ index: Int, tag: Int) throws -> SimpleASN1Node {
        guard let value = fields[index], value.tag == tag else { throw invalid }
        return value
    }
    private static func checkTypes(_ fields: [Int: SimpleASN1Node], _ expected: [Int: Int]) throws {
        for (index, tag) in expected { if let field = fields[index], field.tag != tag { throw invalid } }
    }
    private static func nonnegative(_ node: SimpleASN1Node) throws {
        guard let first = node.value.first, first & 0x80 == 0,
              node.value.count == 1 || first != 0 || node.value[1] & 0x80 != 0 else { throw invalid }
    }
    private static func number(_ node: SimpleASN1Node, range: ClosedRange<Int>) throws -> Int {
        try nonnegative(node)
        var result = 0
        for byte in node.value {
            guard result <= (Int.max >> 8) else { throw invalid }
            result = (result << 8) | Int(byte)
        }
        guard range.contains(result) else { throw invalid }
        return result
    }
    private static func canonicalLengths(_ node: SimpleASN1Node) -> Bool {
        var tagBytes = 1
        if node.encodedBytes[0] & 0x1F == 0x1F {
            while node.encodedBytes[tagBytes] & 0x80 != 0 { tagBytes += 1 }
            tagBytes += 1
        }
        var length = node.value.count, lengthBytes = 1
        if length >= 128 { while length > 0 { lengthBytes += 1; length >>= 8 } }
        return node.headerLength == tagBytes + lengthBytes && node.children.allSatisfy(canonicalLengths)
    }
}
