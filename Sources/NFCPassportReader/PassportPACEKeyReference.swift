//
//  PassportPACEKeyReference.swift
//  NFCPassportReader
//
//  Created for standards-coverage hardening.
//

import Foundation

/// Password/reference type used for PACE key derivation.
///
/// Most passport workflows use `.mrz`. Some documents or inspection systems can
/// use CAN, PIN, or PUK credentials instead. The caller is responsible for
/// collecting and protecting the corresponding credential value.
@available(iOS 13, macOS 10.15, *)
public enum PassportPACEKeyReference: UInt8, Sendable, Equatable {
    case mrz = 0x01
    case can = 0x02
    case pin = 0x03
    case puk = 0x04
}
