//
//  PassportDataGroupReadPolicy.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
struct PassportDataGroupReadPolicy {
    let requestedDataGroups: [DataGroupId]
    let readAllDataGroups: Bool
    let skipSecureElements: Bool
    let photoPolicy: PassportPhotoPolicy

    static func requestedDataGroups(
        tags: [DataGroupId],
        photoPolicy: PassportPhotoPolicy,
        securityPolicy: PassportReaderSecurityPolicy
    ) -> [DataGroupId] {
        let effectivePhotoPolicy = securityPolicy.apply(to: photoPolicy)
        let requested = tags.isEmpty && securityPolicy == .identityOnly
            ? PassportScanProfile.identityOnly.dataGroups
            : tags
        return effectivePhotoPolicy.apply(to: requested)
    }

    func apply(to dataGroups: [DataGroupId]) -> [DataGroupId] {
        var filtered = dataGroups

        if skipSecureElements {
            filtered.removeAll { $0 == .DG3 || $0 == .DG4 }
        }

        filtered = photoPolicy.apply(to: filtered)

        if !readAllDataGroups {
            let requestedSet = Set(requestedDataGroups)
            filtered = filtered.filter { requestedSet.contains($0) }
        }

        return filtered
    }
}
