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
        if let value = String(bytes: bytes, encoding: .utf8) {
            return value
        }

        return String(decoding: bytes, as: UTF8.self)
    }
}
