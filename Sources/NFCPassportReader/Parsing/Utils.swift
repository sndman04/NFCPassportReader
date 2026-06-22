//
//  Utils.swift
//  NFCTest
//
//  Created by Andy Qua on 09/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation

import CommonCrypto
import CryptoTokenKit

#if canImport(CryptoKit)
    import CryptoKit
#endif

private extension UInt8 {
    var hexString: String {
        String(Self.uppercaseHexDigits[Int(self >> 4)]) + String(Self.uppercaseHexDigits[Int(self & 0x0F)])
    }

    static let uppercaseHexDigits = Array("0123456789ABCDEF")
    static let lowercaseHexDigits = Array("0123456789abcdef")
}

extension Int {
    var hexString: String {
        let string = String(self, radix: 16, uppercase: true)
        return string.count == 1 ? "0" + string : string
    }
}

extension StringProtocol {
    subscript(bounds: CountableClosedRange<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(start, offsetBy: bounds.count)
        return self[start..<end]
    }
    
    subscript(bounds: CountableRange<Int>) -> SubSequence {
        let start = index(startIndex, offsetBy: bounds.lowerBound)
        let end = index(start, offsetBy: bounds.count)
        return self[start..<end]
    }
    
    func index(of string: Self, options: String.CompareOptions = []) -> Index? {
        return range(of: string, options: options)?.lowerBound
    }

}


func binToHexRep( _ val : [UInt8], asArray : Bool = false ) -> String {
    if asArray {
        var string = "["
        string.reserveCapacity(2 + val.count * 6)
        for x in val {
            string += "0x"
            string.append(UInt8.lowercaseHexDigits[Int(x >> 4)])
            string.append(UInt8.lowercaseHexDigits[Int(x & 0x0F)])
            string += ", "
        }
        string += "]"
        return string
    }

    var string = ""
    string.reserveCapacity(val.count * 2)
    for x in val {
        string.append(UInt8.uppercaseHexDigits[Int(x >> 4)])
        string.append(UInt8.uppercaseHexDigits[Int(x & 0x0F)])
    }
    return string
}

func binToHexRep( _ val : UInt8 ) -> String {
    val.hexString
}

func binToHex( _ val: UInt8 ) -> Int {
    Int(val)
}

func binToHex( _ val: [UInt8] ) -> UInt64 {
    guard val.count <= MemoryLayout<UInt64>.size else {
        return 0
    }

    return val.reduce(UInt64(0)) { partial, byte in
        (partial << 8) | UInt64(byte)
    }
}

func binToHex( _ val: ArraySlice<UInt8> ) -> UInt64 {
    guard val.count <= MemoryLayout<UInt64>.size else {
        return 0
    }

    return val.reduce(UInt64(0)) { partial, byte in
        (partial << 8) | UInt64(byte)
    }
}


func hexToBin( _ val : UInt64 ) -> [UInt8] {
    if val == 0 {
        return [0]
    }

    var value = val
    var bytes: [UInt8] = []
    bytes.reserveCapacity(MemoryLayout<UInt64>.size)
    while value > 0 {
        bytes.append(UInt8(value & 0xFF))
        value >>= 8
    }
    return Array(bytes.reversed())
}

func binToInt( _ val: ArraySlice<UInt8> ) -> Int {
    val.reduce(0) { partial, byte in
        (partial << 8) | Int(byte)
    }
}

func binToInt( _ val: [UInt8] ) -> Int {
    val.reduce(0) { partial, byte in
        (partial << 8) | Int(byte)
    }
}

func intToBin(_ data : Int, pad : Int = 2) -> [UInt8] {
    guard data >= 0 else {
        return []
    }

    if pad == 2 {
        guard data > 0xFF else {
            return [UInt8(data & 0xFF)]
        }

        return intToBytes(val: data, removePadding: true)
    }

    return [UInt8((data >> 8) & 0xFF), UInt8(data & 0xFF)]
}

/// 'AABB' --> \xaa\xbb'"""
func hexRepToBin(_ val : String) -> [UInt8] {
    let bytes = Array(val.utf8)
    var output : [UInt8] = []
    output.reserveCapacity((bytes.count + 1) / 2)

    var index = 0
    while index < bytes.count {
        guard let high = hexNibble(bytes[index]) else {
            return []
        }

        if index + 1 < bytes.count {
            guard let low = hexNibble(bytes[index + 1]) else {
                return []
            }
            output.append((high << 4) | low)
        } else {
            output.append(high)
        }
        index += 2
    }
    return output
}

private func hexNibble(_ byte: UInt8) -> UInt8? {
    switch byte {
    case 48...57:
        return byte - 48
    case 65...70:
        return byte - 55
    case 97...102:
        return byte - 87
    default:
        return nil
    }
}

func xor(_ kifd : [UInt8], _ response_kicc : [UInt8] ) -> [UInt8] {
    var kseed = [UInt8]()
    kseed.reserveCapacity(min(kifd.count, response_kicc.count))
    for (left, right) in zip(kifd, response_kicc) {
        kseed.append(left ^ right)
    }
    return kseed
}

func generateRandomUInt8Array( _ size: Int ) -> [UInt8] {
    
    var ret : [UInt8] = []
    ret.reserveCapacity(size)
    for _ in 0 ..< size {
        ret.append( UInt8(arc4random_uniform(UInt32(UInt8.max) + 1)) )
    }
    return ret
}

func pad(_ toPad : [UInt8], blockSize : Int) -> [UInt8] {
    
    var ret = toPad + [0x80]
    ret.reserveCapacity(((ret.count + blockSize - 1) / blockSize) * blockSize)
    while ret.count % blockSize != 0 {
        ret.append(0x00)
    }
    return ret
}

func unpad( _ tounpad : [UInt8]) -> [UInt8] {
    guard !tounpad.isEmpty else {
        return []
    }

    var i = tounpad.count-1
    while i > 0 && tounpad[i] == 0x00 {
        i -= 1
    }
    
    if tounpad[i] == 0x80 {
        return [UInt8](tounpad[0..<i])
    } else {
        // no padding
        return tounpad
    }
}

func strictUnpad(_ toUnpad: [UInt8]) -> [UInt8]? {
    guard !toUnpad.isEmpty else {
        return nil
    }

    var index = toUnpad.count - 1
    while index > 0 && toUnpad[index] == 0x00 {
        index -= 1
    }

    guard toUnpad[index] == 0x80 else {
        return nil
    }

    return [UInt8](toUnpad[0..<index])
}

@available(iOS 13, macOS 10.15, *)
func mac(algoName: SecureMessagingSupportedAlgorithms, key : [UInt8], msg : [UInt8]) -> [UInt8] {
    if algoName == .DES {
        return desMAC(key: key, msg: msg)
    } else {
        return aesMAC(key: key, msg: msg)
    }
}

@available(iOS 13, macOS 10.15, *)
func desMAC(key : [UInt8], msg : [UInt8]) -> [UInt8]{
    guard key.count >= 16 else {
        return []
    }
    
    let size = msg.count / 8
    var y : [UInt8] = [0,0,0,0,0,0,0,0]
    let leftKey = [UInt8](key[0..<8])
    let rightKey = [UInt8](key[8..<16])
    for i in 0 ..< size {
        let tmp = [UInt8](msg[i*8 ..< i*8+8])
        y = DESEncrypt(key: leftKey, message: tmp, iv: y)
    }
    let iv : [UInt8] = [0,0,0,0,0,0,0,0]
    let b = DESDecrypt(key: rightKey, message: y, iv: iv, options:UInt32(kCCOptionECBMode))
    let a = DESEncrypt(key: leftKey, message: b, iv: iv, options:UInt32(kCCOptionECBMode))
    
    return a
}

@available(iOS 13, macOS 10.15, *)
func aesMAC( key: [UInt8], msg : [UInt8] ) -> [UInt8] {
    let mac = OpenSSLUtils.generateAESCMAC( key: key, message:msg )
    return mac
}

@available(iOS 13, macOS 10.15, *)
func wrapDO( b : UInt8, arr : [UInt8] ) -> [UInt8] {
    let length = asn1LengthBytes(for: arr.count)
    var result: [UInt8] = []
    result.reserveCapacity(1 + length.count + arr.count)
    result.append(b)
    result.append(contentsOf: length)
    result.append(contentsOf: arr)
    return result
}

@available(iOS 13, macOS 10.15, *)
func unwrapDO( tag : UInt8, wrappedData : [UInt8]) throws -> [UInt8] {
    guard wrappedData.count >= 2,
          wrappedData[0] == tag else {
        throw NFCPassportReaderError.InvalidASN1Value
    }

    let (length, lengthByteCount) = try asn1Length(wrappedData[1...])
    let valueOffset = 1 + lengthByteCount
    let valueEnd = valueOffset + length
    guard valueEnd == wrappedData.count else {
        throw NFCPassportReaderError.InvalidASN1Value
    }

    return [UInt8](wrappedData[valueOffset ..< valueEnd])
}

private func asn1LengthBytes(for length: Int) -> [UInt8] {
    if length < 0x80 {
        return [UInt8(length)]
    }
    if length <= 0xFF {
        return [0x81, UInt8(length)]
    }
    if length <= 0xFFFF {
        return [0x82, UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
    }
    if length <= 0xFFFFFF {
        return [0x83, UInt8((length >> 16) & 0xFF), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
    }
    return [0x84, UInt8((length >> 24) & 0xFF), UInt8((length >> 16) & 0xFF), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)]
}


func intToBytes( val: Int, removePadding:Bool) -> [UInt8] {
    guard val >= 0 else {
        return []
    }

    if val == 0 {
        return [0]
    }
    var data = withUnsafeBytes(of: val.bigEndian, Array.init)

    if removePadding {
        // Remove initial 0 bytes
        for i in 0 ..< data.count {
            if data[i] != 0 {
                data = [UInt8](data[i...])
                break
            }
        }
    }
    return data
}

@available(iOS 13, macOS 10.15, *)
func oidToBytes(oid : String, replaceTag : Bool) -> [UInt8] {
    var encOID = OpenSSLUtils.asn1EncodeOID(oid: oid)
    
    if replaceTag {
        guard !encOID.isEmpty else {
            return []
        }

        // Replace tag (0x06) with 0x80
        encOID[0] = 0x80
    }
    return encOID
}



/// Take an asn.1 length, and return a couple with the decoded length in hexa and the total length of the encoding (1,2 or 3 bytes)
///
/// Using Basic Encoding Rules (BER):
/// If the first byte is <= 0x7F (0-127), then this is the total length of the data
/// If the first byte is 0x81 then the length is the value of the next byte
/// If the first byte is 0x82 then the length is the value of the next two bytes
/// If the first byte is 0x80 then the length is indefinite (never seen this and not sure exactle what it means)
/// e.g.
/// if the data was 0x02, 0x11, 0x12, then the amount of data we have to read is two bytes, and the actual data is [0x11, 0x12]
/// If the length was 0x81,0x80,....... then we know that the data length is contained in the next byte - 0x80 (128), so the amount of data to read is 128 bytes
/// If the length was 0x82,0x01,0x01,....... then we know that the data length is contained in the next 2 bytes - 0x01, 0x01 (257) so the amount of data to read is 257 bytes
///
/// @param data: A length value encoded in the asn.1 format.
/// @type data: A binary string.
/// @return: A tuple with the decoded hexa length and the length of the asn.1 encoded value.
/// @raise asn1Exception: If the parameter does not follow the asn.1 notation.

@available(iOS 13, macOS 10.15, *)
func asn1Length( _ data: ArraySlice<UInt8> ) throws -> (Int, Int) {
    guard let firstByte = data.first else {
        throw NFCPassportReaderError.CannotDecodeASN1Length
    }

    if firstByte < 0x80 {
        return (Int(firstByte), 1)
    }

    let lengthByteCount = Int(firstByte & 0x7F)
    guard lengthByteCount > 0,
          lengthByteCount <= 4,
          data.count >= lengthByteCount + 1 else {
        throw NFCPassportReaderError.CannotDecodeASN1Length
    }

    var value = 0
    var index = data.index(after: data.startIndex)
    for _ in 0 ..< lengthByteCount {
        value = (value << 8) | Int(data[index])
        index = data.index(after: index)
    }

    guard value <= Int(Int32.max) else {
        throw NFCPassportReaderError.CannotDecodeASN1Length
    }

    return (value, lengthByteCount + 1)
}

@available(iOS 13, macOS 10.15, *)
func asn1Length(_ data : [UInt8]) throws -> (Int, Int)  {
    try asn1Length(data[...])
}

/// Convert a length to asn.1 format
/// @param data: The value to encode in asn.1
/// @type data: An integer (hexa)
/// @return: The asn.1 encoded value
/// @rtype: A binary string
/// @raise asn1Exception: If the parameter is too big, must be >= 0 and <= FFFF
@available(iOS 13, macOS 10.15, *)
func toAsn1Length(_ data : Int) throws -> [UInt8] {
    guard data >= 0 else {
        throw NFCPassportReaderError.InvalidASN1Value
    }

    if data < 0x80 {
        return [UInt8(data)]
    }
    if data >= 0x80 && data <= 0xFF {
        return [0x81, UInt8(data)]
    }
    if data >= 0x0100 && data <= 0xFFFF {
        return [0x82, UInt8((data >> 8) & 0xFF), UInt8(data & 0xFF)]
    }
    if data >= 0x010000 && data <= 0xFFFFFF {
        return [0x83, UInt8((data >> 16) & 0xFF), UInt8((data >> 8) & 0xFF), UInt8(data & 0xFF)]
    }
    if data >= 0x01000000 && data <= 0x7FFFFFFF {
        return [0x84, UInt8((data >> 24) & 0xFF), UInt8((data >> 16) & 0xFF), UInt8((data >> 8) & 0xFF), UInt8(data & 0xFF)]
    }
    
    throw NFCPassportReaderError.InvalidASN1Value
}
        


/// This function calculates a  Hash of the input data based on the input algorithm
/// @param data: a byte array of data
/// @param hashAlgorithm: the hash algorithm to be used - supported ones are SHA1, SHA224, SHA256, SHA384 and SHA512
///        Currently specifying any others return empty array
/// @return: A hash of the data
@available(iOS 13, macOS 10.15, *)
func calcHash( data: [UInt8], hashAlgorithm: String ) throws -> [UInt8] {
    var ret : [UInt8] = []
    
    let hashAlgorithm = hashAlgorithm.lowercased()
    if hashAlgorithm == "sha1" {
        ret = calcSHA1Hash(data)
    } else if hashAlgorithm == "sha224" {
        ret = calcSHA224Hash(data)
    } else if hashAlgorithm == "sha256" {
        ret = calcSHA256Hash(data)
    } else if hashAlgorithm == "sha384" {
        ret = calcSHA384Hash(data)
    } else if hashAlgorithm == "sha512" {
        ret = calcSHA512Hash(data)
    } else {
        throw NFCPassportReaderError.InvalidHashAlgorithmSpecified
    }
        
    return ret
}


/// This function calculates a SHA1 Hash of the input data
/// @param data: a byte array of data
/// @return: A SHA1 hash of the data
@available(iOS 13, macOS 10.15, *)
func calcSHA1Hash( _ data: [UInt8] ) -> [UInt8] {
    #if canImport(CryptoKit)
    var sha1 = Insecure.SHA1()
    sha1.update(data: data)
    let hash = sha1.finalize()
    
    return Array(hash)
    #else
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
    }
    return digest
    #endif
}

/// This function calculates a SHA224 Hash of the input data
/// @param data: a byte array of data
/// @return: A SHA224 hash of the data
@available(iOS 13, macOS 10.15, *)
func calcSHA224Hash( _ data: [UInt8] ) -> [UInt8] {
    
    var digest = [UInt8](repeating: 0, count:Int(CC_SHA224_DIGEST_LENGTH))
    
    data.withUnsafeBytes {
        _ = CC_SHA224($0.baseAddress, CC_LONG(data.count), &digest)
    }
    return digest
}

/// This function calculates a SHA256 Hash of the input data
/// @param data: a byte array of data
/// @return: A SHA256 hash of the data
@available(iOS 13, macOS 10.15, *)
func calcSHA256Hash( _ data: [UInt8] ) -> [UInt8] {
    #if canImport(CryptoKit)
    var sha256 = SHA256()
    sha256.update(data: data)
    let hash = sha256.finalize()
    
    return Array(hash)
    #else
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &digest)
    }
    return digest
    #endif
}

/// This function calculates a SHA512 Hash of the input data
/// @param data: a byte array of data
/// @return: A SHA512 hash of the data
@available(iOS 13, macOS 10.15, *)
func calcSHA512Hash( _ data: [UInt8] ) -> [UInt8] {
    #if canImport(CryptoKit)
    var sha512 = SHA512()
    sha512.update(data: data)
    let hash = sha512.finalize()
    
    return Array(hash)
    #else
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA512($0.baseAddress, CC_LONG(data.count), &digest)
    }
    return digest
    #endif
}

/// This function calculates a SHA384 Hash of the input data
/// @param data: a byte array of data
/// @return: A SHA384 hash of the data
@available(iOS 13, macOS 10.15, *)
func calcSHA384Hash( _ data: [UInt8] ) -> [UInt8] {
    #if canImport(CryptoKit)
    var sha384 = SHA384()
    sha384.update(data: data)
    let hash = sha384.finalize()
    
    return Array(hash)
    #else
    var digest = [UInt8](repeating: 0, count: Int(CC_SHA384_DIGEST_LENGTH))
    data.withUnsafeBytes {
        _ = CC_SHA384($0.baseAddress, CC_LONG(data.count), &digest)
    }
    return digest
    #endif
}
