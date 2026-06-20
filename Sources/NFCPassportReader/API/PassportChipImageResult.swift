//
//  PassportChipImageResult.swift
//  NFCPassportReader
//
//  Created for privacy-safe fork integration.
//

import Foundation

/// Public image format for an explicitly requested passport-chip face image.
@available(iOS 13, macOS 10.15, *)
public enum PassportChipImageFormat: Sendable, Equatable {
    case jpeg
    case jpeg2000
    case unknown
}

/// Explicitly requested face-image bytes from DG2.
///
/// This value contains sensitive biometric data. Host apps should avoid logging, uploading,
/// persisting, sharing, or attaching it to diagnostics unless that use has been separately
/// reviewed and disclosed to the user.
@available(iOS 13, macOS 10.15, *)
public struct PassportChipImageResult: Sendable, Equatable {
    public let data: Data
    public let format: PassportChipImageFormat
    public let mimeType: String?
    public let width: Int?
    public let height: Int?

    init?(dataGroup: DataGroup2, photoPolicy: PassportPhotoPolicy) {
        guard photoPolicy == .read,
              !dataGroup.imageData.isEmpty else {
            return nil
        }

        self.data = Data(dataGroup.imageData)
        self.format = PassportChipImageFormat(imageDataType: dataGroup.imageDataType)
        self.mimeType = format.mimeType
        self.width = dataGroup.imageWidth > 0 ? dataGroup.imageWidth : nil
        self.height = dataGroup.imageHeight > 0 ? dataGroup.imageHeight : nil
    }
}

@available(iOS 13, macOS 10.15, *)
private extension PassportChipImageFormat {
    init(imageDataType: Int) {
        switch imageDataType {
        case 0x00:
            self = .jpeg
        case 0x01:
            self = .jpeg2000
        default:
            self = .unknown
        }
    }

    var mimeType: String? {
        switch self {
        case .jpeg:
            return "image/jpeg"
        case .jpeg2000:
            return "image/jp2"
        case .unknown:
            return nil
        }
    }
}
