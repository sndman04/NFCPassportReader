//
//  ResponseAPDU.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 09/02/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

#if !os(macOS)

@available(iOS 13, *)
struct ResponseAPDU {
    
    var data : [UInt8]
    var sw1 : UInt8
    var sw2 : UInt8
    
    init(data: [UInt8], sw1: UInt8, sw2: UInt8) {
        self.data = data
        self.sw1 = sw1
        self.sw2 = sw2
    }
}

#endif
