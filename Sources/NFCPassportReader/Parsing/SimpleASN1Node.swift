//
//  SimpleASN1Node.swift
//  NFCPassportReader
//
//  Created for structured LDS security-object parsing.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
struct SimpleASN1Node: CustomDebugStringConvertible {
    private static let maxDepth = 64
    private static let maxNodes = 10_000

    let offset: Int
    let tag: Int
    let headerLength: Int
    let encodedBytes: [UInt8]
    let value: [UInt8]
    let children: [SimpleASN1Node]

    var debugDescription: String {
        let childDescriptions = children.map(\.debugDescription).joined(separator: "")
        return "tag:\(tag), hl=\(headerLength), l=\(value.count): <redacted>\n" + childDescriptions
    }

    var integerValue: Int? {
        guard tag == 0x02,
              !value.isEmpty,
              value[0] & 0x80 == 0 else { return nil }

        var result = 0
        for byte in value {
            let shifted = result.multipliedReportingOverflow(by: 256)
            guard !shifted.overflow else { return nil }

            let added = shifted.partialValue.addingReportingOverflow(Int(byte))
            guard !added.overflow else { return nil }
            result = added.partialValue
        }
        return result
    }

    var objectIdentifier: String? {
        guard tag == 0x06, !value.isEmpty else { return nil }

        var arcs: [Int] = []
        var current = 0
        for byte in value {
            let shifted = current.multipliedReportingOverflow(by: 128)
            guard !shifted.overflow else { return nil }

            let added = shifted.partialValue.addingReportingOverflow(Int(byte & 0x7F))
            guard !added.overflow else { return nil }
            current = added.partialValue

            if byte & 0x80 == 0 {
                arcs.append(current)
                current = 0
            }
        }

        guard current == 0,
              let firstSubidentifier = arcs.first else { return nil }

        let firstArc = min(firstSubidentifier / 40, 2)
        let secondArc = firstSubidentifier - (firstArc * 40)
        let parts = [firstArc, secondArc] + arcs.dropFirst()
        return parts.map(String.init).joined(separator: ".")
    }

    static func parse(_ bytes: [UInt8], diagnostic: ((PassportParserDiagnostic) -> Void)? = nil) throws -> SimpleASN1Node {
        var remainingNodes = maxNodes
        let (node, offset) = try parseNode(bytes, from: 0, limit: bytes.count, depth: 0, remainingNodes: &remainingNodes, diagnostic: diagnostic)
        guard offset == bytes.count else {
            diagnostic?(.init(expectedLength: offset, actualLength: bytes.count, offset: offset))
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        return node
    }

    private static func parseNode(
        _ bytes: [UInt8],
        from offset: Int,
        limit: Int,
        depth: Int,
        remainingNodes: inout Int,
        diagnostic: ((PassportParserDiagnostic) -> Void)?
    ) throws -> (SimpleASN1Node, Int) {
        guard depth <= maxDepth,
              remainingNodes > 0,
              offset < limit else {
            diagnostic?(.init(actualLength: limit, offset: offset))
            throw NFCPassportReaderError.InvalidASN1Structure
        }
        remainingNodes -= 1

        var cursor = offset
        let tag: Int
        let length: Int
        let lengthSize: Int
        do {
            tag = try readTag(bytes, cursor: &cursor, limit: limit)
            (length, lengthSize) = try asn1Length(bytes[cursor ..< min(cursor + 5, limit)])
        } catch {
            diagnostic?(.init(actualLength: max(0, limit - cursor), offset: cursor))
            throw error
        }
        cursor += lengthSize
        let headerLength = cursor - offset
        guard length >= 0, cursor + length <= limit else {
            diagnostic?(.init(actualTag: tag, expectedLength: length, actualLength: limit - cursor, offset: offset))
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        let valueStart = cursor
        let valueEnd = cursor + length
        let value = [UInt8](bytes[valueStart ..< valueEnd])
        var children: [SimpleASN1Node] = []

        if isConstructedTag(tag) {
            var childOffset = valueStart
            while childOffset < valueEnd {
                let (child, nextOffset) = try parseNode(
                    bytes,
                    from: childOffset,
                    limit: valueEnd,
                    depth: depth + 1,
                    remainingNodes: &remainingNodes,
                    diagnostic: diagnostic
                )
                children.append(child)
                childOffset = nextOffset
            }
        }

        let encodedBytes = [UInt8](bytes[offset ..< valueEnd])
        return (
            SimpleASN1Node(
                offset: offset,
                tag: tag,
                headerLength: headerLength,
                encodedBytes: encodedBytes,
                value: value,
                children: children
            ),
            valueEnd
        )
    }

    private static func readTag(_ bytes: [UInt8], cursor: inout Int, limit: Int) throws -> Int {
        guard cursor < limit else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        let first = bytes[cursor]
        cursor += 1
        if first & 0x1F != 0x1F {
            return Int(first)
        }

        var tag = Int(first)
        repeat {
            guard cursor < limit else {
                throw NFCPassportReaderError.InvalidASN1Structure
            }
            let byte = bytes[cursor]
            cursor += 1
            guard tag <= Int.max >> 8 else {
                throw NFCPassportReaderError.InvalidASN1Structure
            }
            tag = (tag << 8) | Int(byte)
            if byte & 0x80 == 0 {
                return tag
            }
        } while true
    }

    private static func isConstructedTag(_ tag: Int) -> Bool {
        let firstByte = UInt8((tag >> (max(0, (byteCount(tag) - 1)) * 8)) & 0xFF)
        return firstByte & 0x20 == 0x20
    }

    private static func byteCount(_ value: Int) -> Int {
        var value = value
        var count = 1
        while value > 0xFF {
            value >>= 8
            count += 1
        }
        return count
    }
}
