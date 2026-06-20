//
//  DataGroupHash.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 09/02/2021.
//  Copyright © 2021 Andy Qua. All rights reserved.
//

@available(iOS 13, macOS 10.15, *)
struct DataGroupHash {
    var id: String
    var sodHash: String
    var computedHash : String
    var match : Bool
}

