//
//  NFCViewDisplayMessage.swift
//  NFCPassportReader
//
//  Created by Andy Qua on 09/02/2021.
//

import Foundation

@available(iOS 13, macOS 10.15, *)
public enum NFCViewDisplayMessage {
    case requestPresentPassport
    case authenticatingWithPassport(Int)
    case readingDataGroupProgress(DataGroupId, Int)
    case error(NFCPassportReaderError)
    case activeAuthentication
    case successfulRead
}

public typealias PassportReaderDisplayMessageHandler = @Sendable (NFCViewDisplayMessage) -> String?

@available(iOS 13, macOS 10.15, *)
extension NFCViewDisplayMessage {
    public var description: String {
        switch self {
            case .requestPresentPassport:
                return "Hold your iPhone near an NFC enabled passport."
            case .authenticatingWithPassport(let progress):
                let progressString = handleProgress(percentualProgress: progress)
                return "Authenticating with passport...\n\n\(progressString)"
            case .readingDataGroupProgress(let dataGroup, let progress):
                let progressString = handleProgress(percentualProgress: progress)
                return "Reading \(dataGroup)...\n\n\(progressString)"
            case .error(let tagError):
                if case NFCPassportReaderError.MoreThanOneTagFound = tagError {
                    return "More than one NFC tag was found. Present only one passport."
                }
                let failure = tagError.privacySafeFailure
                return "\(failure.userMessage) \(failure.recoverySuggestion)"
            case .activeAuthentication:
                return "Authenticating..."
            case .successfulRead:
                return "Passport read successfully."
        }
    }
    
    func handleProgress(percentualProgress: Int) -> String {
        let p = min(max(percentualProgress, 0), 100) / 20
        let full = String(repeating: "🟢 ", count: p)
        let empty = String(repeating: "⚪️ ", count: 5-p)
        return "\(full)\(empty)"
    }
}
