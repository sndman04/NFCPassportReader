//
//  PassportNFCSessionFactory.swift
//

import Dispatch

#if !os(macOS)
@preconcurrency import CoreNFC

@available(iOS 15, *)
enum PassportNFCSessionFactory {
    static let delegateQueue: DispatchQueue = .main

    @MainActor
    static func makeTagReaderSession(delegate: NFCTagReaderSessionDelegate) -> NFCTagReaderSession? {
        NFCTagReaderSession(pollingOption: [.iso14443], delegate: delegate, queue: delegateQueue)
    }
}
#endif
