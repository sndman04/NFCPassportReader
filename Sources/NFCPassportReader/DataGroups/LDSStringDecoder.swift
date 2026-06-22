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

@available(iOS 13, macOS 10.15, *)
enum LDSDateDecoder {
    static func decodeEightDigitDate(_ bytes: [UInt8]) throws -> String {
        guard bytes.count == 8,
              bytes.allSatisfy({ byte in byte >= 0x30 && byte <= 0x39 }) else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        let value = String(decoding: bytes, as: UTF8.self)
        guard isValidEightDigitCalendarDate(value) else {
            throw NFCPassportReaderError.InvalidASN1Structure
        }

        return value
    }

    private static func isValidEightDigitCalendarDate(_ value: String) -> Bool {
        guard let year = Int(value.prefix(4)),
              let month = Int(value.dropFirst(4).prefix(2)),
              let day = Int(value.suffix(2)) else {
            return false
        }

        guard year >= 1 else {
            return false
        }

        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0) ?? calendar.timeZone

        var components = DateComponents()
        components.calendar = calendar
        components.timeZone = calendar.timeZone
        components.year = year
        components.month = month
        components.day = day

        guard let date = calendar.date(from: components) else {
            return false
        }

        let resolved = calendar.dateComponents([.year, .month, .day], from: date)
        return resolved.year == year && resolved.month == month && resolved.day == day
    }
}
