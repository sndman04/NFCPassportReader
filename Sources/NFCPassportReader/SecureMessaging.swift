//
//  SecureMessaging.swift
//  NFCTest
//
//  Created by Andy Qua on 09/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation

public enum SecureMessagingSupportedAlgorithms {
    case DES
    case AES
}

#if !os(macOS)
import CoreNFC


/// This class implements the secure messaging protocol.
/// The class is a new layer that comes between the reader and the iso7816.
/// It gives a new transmit method that takes an APDU object formed by the iso7816 layer,
/// ciphers it following the doc9303 specification, sends the ciphered APDU to the reader
/// layer and returns the unciphered APDU.
@available(iOS 13, *)
public class SecureMessaging {
    private var ksenc : [UInt8]
    private var ksmac : [UInt8]
    private var ssc : [UInt8]
    private let algoName : SecureMessagingSupportedAlgorithms
    private let padLength : Int
        
    public init( encryptionAlgorithm : SecureMessagingSupportedAlgorithms = .DES, ksenc : [UInt8], ksmac : [UInt8], ssc : [UInt8]) {
        self.ksenc = ksenc
        self.ksmac = ksmac
        self.ssc = ssc
        self.algoName = encryptionAlgorithm
        self.padLength = algoName == .DES ? 8 : 16
    }

    /// Protect the apdu following the doc9303 specification
    func protect(apdu : NFCISO7816APDU, useExtendedMode: Bool = false ) throws -> NFCISO7816APDU {
        self.ssc = self.incSSC()
        let paddedSSC = algoName == .DES ? self.ssc : [UInt8](repeating: 0, count: 8) + ssc


        let cmdHeader = self.maskClassAndPad(apdu: apdu)
        var do87 : [UInt8] = []
        var do97 : [UInt8] = []
        
        if apdu.data != nil {
            do87 = try self.buildD087(apdu: apdu)
        }
        
        let isMSE = apdu.instructionCode == 0x22
        if apdu.expectedResponseLength > 0 && (isMSE ? apdu.expectedResponseLength < 256 : true) {
            do97 = try self.buildD097(apdu: apdu)
        }
        
        let M = cmdHeader + do87 + do97
        
        let N = pad(paddedSSC + M, blockSize:padLength)

        var CC = mac(algoName: algoName, key: self.ksmac, msg: N)
        guard !CC.isEmpty else {
            throw NFCPassportReaderError.UnableToProtectAPDU
        }
        if CC.count > 8 {
            CC = [UInt8](CC[0..<8])
        }
        
        let do8e = self.buildD08E(mac: CC)
        
        // If dataSize > 255 then it will be encoded in 3 bytes with the first byte being 0x00
        // otherwise its a single byte of size
        let size = do87.count + do97.count + do8e.count
        var dataSize: [UInt8]
        if size > 255 || (useExtendedMode && apdu.expectedResponseLength > 231) {
            dataSize = [0x00] + intToBin(size, pad: 4)
        } else {
            dataSize = intToBin(size)
        }
        var protectedAPDU = [UInt8](cmdHeader[0..<4]) + dataSize
        protectedAPDU += do87 + do97 + do8e
            
        // If the data is more that 255, specify the we are using extended length (0x00, 0x00)
        // Thanks to @filom for the fix!
        if size > 255 || (useExtendedMode && apdu.expectedResponseLength > 231) {
            protectedAPDU += [0x00,0x00]
        } else {
            protectedAPDU += [0x00]
        }
        
        guard let newAPDU = NFCISO7816APDU(data: Data(protectedAPDU)) else {
            throw NFCPassportReaderError.UnableToProtectAPDU
        }
        return newAPDU
    }

    /// Unprotect the APDU following the iso7816 specification
    func unprotect(rapdu : ResponseAPDU ) throws -> ResponseAPDU {
        var needCC = false
        var do87 : [UInt8] = []
        var do87Data : [UInt8] = []
        var do99 : [UInt8] = []
        //var do8e : [UInt8] = []
        var offset = 0
        
        self.ssc = self.incSSC()
        let paddedSSC = algoName == .DES ? self.ssc : [UInt8](repeating: 0, count: 8) + ssc
                
        // Check for a SM error
        if(rapdu.sw1 != 0x90 || rapdu.sw2 != 0x00) {
            return rapdu
        }

        let rapduBin = rapdu.data + [rapdu.sw1, rapdu.sw2]
        guard !rapduBin.isEmpty else {
            throw NFCPassportReaderError.MissingMandatoryFields
        }
        
        // DO'87'
        // Mandatory if data is returned, otherwise absent
        if rapduBin[0] == 0x87 {
            let (encDataLength, o) = try asn1Length(rapduBin[1...])
            offset = 1 + o

            guard offset < rapduBin.count,
                  offset + Int(encDataLength) <= rapduBin.count else {
                throw NFCPassportReaderError.D087Malformed
            }
            
            if rapduBin[offset] != 0x1 {
                throw NFCPassportReaderError.D087Malformed
            }
            
            do87 = [UInt8](rapduBin[0 ..< offset + Int(encDataLength)])
            do87Data = [UInt8](rapduBin[offset+1 ..< offset + Int(encDataLength)])
            offset += Int(encDataLength)
            needCC = true
        }
        
        //DO'99'
        // Mandatory, only absent if SM error occurs
        guard rapduBin.count >= offset + 5 else {
            let returnSw1 = (rapduBin.count >= offset+3) ? rapduBin[offset+2] : 0;
            let returnSw2 = (rapduBin.count >= offset+4) ? rapduBin[offset+3] : 0;
            return ResponseAPDU(data: [], sw1: returnSw1, sw2: returnSw2);
        }

        do99 = [UInt8](rapduBin[offset..<offset+4])
        let sw1 = rapduBin[offset+2]
        let sw2 = rapduBin[offset+3]
        offset += 4
        needCC = true
        
        if do99[0] != 0x99 || do99[1] != 0x02 {
            //SM error, return the error code
            return ResponseAPDU(data: [], sw1: sw1, sw2: sw2)
        }
        
        // DO'8E'
        //Mandatory if DO'87' and/or DO'99' is present
        if offset < rapduBin.count, rapduBin[offset] == 0x8E {
            guard offset + 2 <= rapduBin.count else {
                throw NFCPassportReaderError.MissingMandatoryFields
            }

            let ccLength : Int = Int(rapduBin[offset+1])
            guard offset + 2 + ccLength <= rapduBin.count else {
                throw NFCPassportReaderError.MissingMandatoryFields
            }

            let CC = [UInt8](rapduBin[offset+2 ..< offset+2+ccLength])
            // do8e = [UInt8](rapduBin[offset ..< offset+2+ccLength])
            
            // CheckCC
            let K = pad(paddedSSC + do87 + do99, blockSize:padLength)
            var CCb = mac(algoName: algoName, key: self.ksmac, msg: K)
            guard !CCb.isEmpty else {
                throw NFCPassportReaderError.UnableToUnprotectAPDU
            }
            if CCb.count > 8 {
                CCb = [UInt8](CCb[0..<8])
            }
            
            let res = (CC == CCb)
            
            if !res {
                throw NFCPassportReaderError.InvalidResponseChecksum
            }

            offset += 2 + ccLength
            guard offset + 2 == rapduBin.count else {
                throw NFCPassportReaderError.MissingMandatoryFields
            }
        }
        else if needCC {
            throw NFCPassportReaderError.MissingMandatoryFields
        }
        
        var data : [UInt8] = []
        if do87Data.count > 0 {
            
            let dec : [UInt8]
            if algoName == .DES {
                dec = tripleDESDecrypt(key: self.ksenc, message: do87Data, iv: [0,0,0,0,0,0,0,0])
            } else {
                // for AES the IV is the ssc with AES/EBC/NOPADDING
                let paddedssc = [UInt8](repeating: 0, count: 8) + ssc
                let iv = AESECBEncrypt(key: ksenc, message: paddedssc)
                guard !iv.isEmpty else {
                    throw NFCPassportReaderError.UnableToUnprotectAPDU
                }

                dec = AESDecrypt(key: self.ksenc, message: do87Data, iv: iv)
            }
            guard !dec.isEmpty else {
                throw NFCPassportReaderError.UnableToUnprotectAPDU
            }

            // There is a payload
            data = unpad(dec)
        }
        return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }

    func maskClassAndPad(apdu : NFCISO7816APDU ) -> [UInt8] {
        let res = pad([0x0c, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter], blockSize: padLength)
        return res
    }
    
    func buildD087(apdu : NFCISO7816APDU) throws -> [UInt8] {
        let encryptedData = try self.padAndEncryptData(apdu)
        let cipher = [0x01] + encryptedData
        let res = try [0x87] + toAsn1Length(cipher.count) + cipher
        return res
    }
    
    func padAndEncryptData(_ apdu : NFCISO7816APDU) throws -> [UInt8] {
        guard let apduData = apdu.data else {
            throw NFCPassportReaderError.UnableToProtectAPDU
        }

        let data = [UInt8](apduData)
        let paddedData = pad( data, blockSize: padLength )
        
        let enc : [UInt8]
        if algoName == .DES {
            enc = tripleDESEncrypt(key: self.ksenc, message: paddedData, iv: [0,0,0,0,0,0,0,0])
        } else {
            // for AES the IV is the ssc with AES/EBC/NOPADDING
            let paddedssc = [UInt8](repeating: 0, count: 8) + ssc
            let iv = AESECBEncrypt(key: ksenc, message: paddedssc)
            guard !iv.isEmpty else {
                throw NFCPassportReaderError.UnableToProtectAPDU
            }

            enc = AESEncrypt(key: self.ksenc, message: paddedData, iv: iv)
        }
        guard !enc.isEmpty else {
            throw NFCPassportReaderError.UnableToProtectAPDU
        }

        return enc
    }
    
    func incSSC() -> [UInt8] {
        var next = self.ssc
        for index in next.indices.reversed() {
            let (value, overflow) = next[index].addingReportingOverflow(1)
            next[index] = value
            if !overflow {
                return next
            }
        }
        return next
    }
    
    func buildD08E(mac : [UInt8]) -> [UInt8] {
        let res : [UInt8] = [0x8E, UInt8(mac.count)] + mac
        return res
    }

    func buildD097(apdu : NFCISO7816APDU) throws -> [UInt8] {
        let le = apdu.expectedResponseLength
        var binLe = intToBin(le)
        if (le == 256 || le == 65536) {
            binLe = [0x00] + (le > 256 ? [0x00] : [])
        }
        
        let res : [UInt8] = try [0x97] + toAsn1Length(binLe.count) + binLe
        return res
    }
    
}
#endif
