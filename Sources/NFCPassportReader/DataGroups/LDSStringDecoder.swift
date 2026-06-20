//
//  LDSStringDecoder.swift
//  NFCPassportReader
//
//  Created for standards-coverage hardening.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
enum LDSStringDecoder {
    static func decode(_ bytes: [UInt8]) -> String {
        guard !bytes.isEmpty else {
            return ""
        }

        if bytes.starts(with: [0xEF, 0xBB, 0xBF]),
           let value = String(bytes: bytes.dropFirst(3), encoding: .utf8) {
            return value
        }

        if bytes.starts(with: [0xFE, 0xFF]),
           let value = String(bytes: bytes.dropFirst(2), encoding: .utf16BigEndian) {
            return value
        }

        if bytes.starts(with: [0xFF, 0xFE]),
           let value = String(bytes: bytes.dropFirst(2), encoding: .utf16LittleEndian) {
            return value
        }

        if looksLikeUTF16BigEndian(bytes),
           let value = String(bytes: bytes, encoding: .utf16BigEndian) {
            return value
        }

        if looksLikeUTF16LittleEndian(bytes),
           let value = String(bytes: bytes, encoding: .utf16LittleEndian) {
            return value
        }

        for encoding in fallbackEncodings {
            if let value = String(bytes: bytes, encoding: encoding) {
                return value
            }
        }

        return String(decoding: bytes, as: UTF8.self)
    }

    private static let fallbackEncodings: [String.Encoding] = [
        .utf8,
        .isoLatin1,
        .windowsCP1252,
        .ascii
    ]

    private static func looksLikeUTF16BigEndian(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 4, bytes.count.isMultiple(of: 2) else {
            return false
        }

        let zeroCount = stride(from: 0, to: bytes.count, by: 2).filter { bytes[$0] == 0x00 }.count
        return zeroCount >= bytes.count / 4
    }

    private static func looksLikeUTF16LittleEndian(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 4, bytes.count.isMultiple(of: 2) else {
            return false
        }

        let zeroCount = stride(from: 1, to: bytes.count, by: 2).filter { bytes[$0] == 0x00 }.count
        return zeroCount >= bytes.count / 4
    }
}
