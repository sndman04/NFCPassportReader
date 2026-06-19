//
//  PassportScanProfile.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// A privacy-conscious data-group policy for passport chip scans.
///
/// Use the smallest profile that fits the app workflow. Reading fewer data
/// groups can reduce scan time and avoids handling optional chip data the app
/// does not need.
@available(iOS 13, macOS 10.15, *)
public enum PassportScanProfile: Sendable, Equatable {
    /// Reads document metadata, SOD, and normalized identity fields.
    case identityOnly

    /// Reads identity data and the face image data group.
    case identityWithPhoto

    /// Reads the groups currently used by the Notary Journal integration for
    /// identity, photo, optional details, and chip/authentication material.
    case fullVerification

    /// Reads an explicit set of data groups.
    case custom([DataGroupId])

    public var dataGroups: [DataGroupId] {
        switch self {
        case .identityOnly:
            return [.COM, .SOD, .DG1]
        case .identityWithPhoto:
            return [.COM, .SOD, .DG1, .DG2]
        case .fullVerification:
            return [.COM, .SOD, .DG1, .DG2, .DG12, .DG14, .DG15]
        case .custom(let dataGroups):
            return dataGroups.uniquedPreservingOrder()
        }
    }
}

private extension Array where Element: Hashable {
    func uniquedPreservingOrder() -> [Element] {
        var seen = Set<Element>()
        return filter { seen.insert($0).inserted }
    }
}

