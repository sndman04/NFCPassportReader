import Foundation

#if !os(macOS)
import CoreNFC

/// Internal control flow, never returned as a public scan error.
@available(iOS 15, *)
enum PassportAccessRecovery: Error {
    case restartPolling

    /// Transport/session interruptions must retain their meaning; neither a
    /// fallback decision nor an application SELECT makes them a credential error.
    static func interruption(from error: Error) -> NFCPassportReaderError? {
        if error is CancellationError { return .UserCanceled }
        if let error = error as? NFCPassportReaderError {
            switch error {
            case .ConnectionError, .TimeOutError, .UserCanceled: return error
            case .NoConnectedTag: return .ConnectionError
            default: return nil
            }
        }
        if let error = error as? NFCReaderError {
            switch error.code {
            case .readerTransceiveErrorTagConnectionLost,
                 .readerTransceiveErrorTagResponseError,
                 .readerTransceiveErrorRetryExceeded,
                 .readerTransceiveErrorTagNotConnected,
                 .readerTransceiveErrorSessionInvalidated,
                 .readerSessionInvalidationErrorSessionTerminatedUnexpectedly: return .ConnectionError
            case .readerSessionInvalidationErrorSessionTimeout: return .TimeOutError
            case .readerSessionInvalidationErrorUserCanceled: return .UserCanceled
            default: return nil
            }
        }
        return nil
    }
}
#endif
