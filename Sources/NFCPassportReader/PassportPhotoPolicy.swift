//
//  PassportPhotoPolicy.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum PassportPhotoPolicy: Sendable, Equatable {
    /// Reads DG2 when requested by the tag list or scan profile.
    case read

    /// Removes DG2 from the requested data groups to avoid reading and storing
    /// passport face image bytes when the host app does not need them.
    case skip

    func apply(to dataGroups: [DataGroupId]) -> [DataGroupId] {
        switch self {
        case .read:
            return dataGroups
        case .skip:
            return dataGroups.filter { $0 != .DG2 }
        }
    }
}

