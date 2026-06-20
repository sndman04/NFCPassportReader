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
    
    public private(set) var imageData : [UInt8] = []
    public private(set) var imageDataItems : [[UInt8]] = []

    public override var datagroupType: DataGroupId { .DG7 }

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }
    
#if !os(macOS)
    func getImage() -> UIImage? {
        if imageData.count == 0 {
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
        
        while hasUnreadBody {
            tag = try getNextTag()
            try verifyTag(tag, equals: 0x5F43)
            let item = try getNextValue()
            guard item.count <= Self.maxImageDataLength else {
                throw NFCPassportReaderError.UnknownImageFormat
            }
            let currentTotal = imageDataItems.reduce(0) { $0 + $1.count }
            guard currentTotal + item.count <= Self.maxTotalImageDataLength else {
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
}
