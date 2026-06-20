//
//  CardAccess+PACESelection.swift
//  NFCPassportReader
//
//  Created for PACE interoperability hardening.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
extension CardAccess {
    var preferredPACEInfo: PACEInfo? {
        paceInfos.first { $0.isImplementedForReading } ?? paceInfo
    }
}
