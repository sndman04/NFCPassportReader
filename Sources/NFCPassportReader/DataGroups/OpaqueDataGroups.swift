//
//  OpaqueDataGroups.swift
//  NFCPassportReader
//
//  Created for standards-coverage hardening.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public class DataGroup3: DataGroup {
    public override var datagroupType: DataGroupId { .DG3 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup4: DataGroup {
    public override var datagroupType: DataGroupId { .DG4 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup5: DataGroup {
    public override var datagroupType: DataGroupId { .DG5 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup6: DataGroup {
    public override var datagroupType: DataGroupId { .DG6 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup8: DataGroup {
    public override var datagroupType: DataGroupId { .DG8 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup9: DataGroup {
    public override var datagroupType: DataGroupId { .DG9 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup10: DataGroup {
    public override var datagroupType: DataGroupId { .DG10 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup13: DataGroup {
    public override var datagroupType: DataGroupId { .DG13 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}

@available(iOS 13, macOS 10.15, *)
public class DataGroup16: DataGroup {
    public override var datagroupType: DataGroupId { .DG16 }

    required init(_ data: [UInt8]) throws {
        try super.init(data)
    }
}
