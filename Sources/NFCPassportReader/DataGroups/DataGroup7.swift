//
//  DataGroup7.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
class DataGroup7 : DataGroup {
    private static let maxImageDataLength = 10 * 1024 * 1024
    private static let maxTotalImageDataLength = 20 * 1024 * 1024
    private static let jpegHeader: [UInt8] = [0xff, 0xd8, 0xff]
    private static let jpeg2000BitmapHeader: [UInt8] = [0x00, 0x00, 0x00, 0x0c, 0x6a, 0x50, 0x20, 0x20, 0x0d, 0x0a]
    private static let jpeg2000CodestreamBitmapHeader: [UInt8] = [0xff, 0x4f, 0xff, 0x51]
    
    public private(set) var imageData : [UInt8] = []
    public private(set) var imageDataItems : [[UInt8]] = []

    public override var datagroupType: DataGroupId { .DG7 }

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
#if !os(macOS)
    func getImage() -> UIImage? {
        guard Self.canDecodeImageData(imageData) else {
            return nil
        }
        
        let image = UIImage(data:Data(imageData) )
        return image
    }
#endif
    
    
    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x02)
        _ = try getNextValue()
        
        var totalImageDataLength = 0
        while hasUnreadBody {
            tag = try getNextTag()
            try verifyTag(tag, equals: 0x5F43)
            let item = try getNextValue()
            guard item.count <= Self.maxImageDataLength else {
                throw NFCPassportReaderError.UnknownImageFormat
            }
            totalImageDataLength += item.count
            guard totalImageDataLength <= Self.maxTotalImageDataLength else {
                throw NFCPassportReaderError.UnknownImageFormat
            }
            imageDataItems.append(item)
        }

        imageData = imageDataItems.first ?? []
    }

    override func removeSensitiveDataForPrivacy() {
        imageData.removeAll(keepingCapacity: false)
        imageDataItems.removeAll(keepingCapacity: false)
        super.removeSensitiveDataForPrivacy()
    }

    private static func canDecodeImageData<T: Collection>(_ data: T) -> Bool where T.Element == UInt8 {
        data.count > 0 &&
            data.count <= maxImageDataLength &&
            (
                data.starts(with: jpegHeader) ||
                data.starts(with: jpeg2000BitmapHeader) ||
                data.starts(with: jpeg2000CodestreamBitmapHeader)
            )
    }
}
