//
//  WDVBinaryUtil.swift
//  SwWidevine
//
//  Created by Developer on 12.07.2024.
//

import Foundation

///Binary integer utils
final class WDVBinaryUtil {
    
    fileprivate init() {}
    
    @inlinable
    static func getLEndianBytes<T: BinaryInteger>(_ val: T) -> Array<UInt8> {
        let size = MemoryLayout.size(ofValue: val)
        var res = Array<UInt8>.init(repeating: 0, count: size)
        if (val is Int8) {
            //Int8 max value is 0x7F -> transform to UInt8 and restart
            let int8Val = Int8(val)
            return getLEndianBytes(UInt8(bitPattern: int8Val))
        }
        let mask: T = 0xFF
        var mutable = val
        for i in (0..<size) {
          res[i] = UInt8(mutable & mask)
            mutable >>= 8
        }
        return res
    }
    
    ///Get bytes from value
    ///- Parameter val: value
    ///- Parameter bigEndian: Extract bytes as big endian order if true, otherwise - as little endian
    @inlinable
    static func getBytes<T: BinaryInteger>(_ val: T, bigEndian: Bool = true) -> [UInt8] {
        let leBytes = getLEndianBytes(val)
        if (bigEndian) {
            return leBytes.reversed()
        }
        return leBytes
    }
    
    ///Get Binary Integer value from bytes
    ///- Parameter buffer: Byte array
    ///- Parameter offset: Byte array offset. Default value is 0
    ///- Parameter bigEndian: Extract bytes as Big-Endian order if true, otherwise - as Little-Endian
    @inlinable
    static func getVal<T: BinaryInteger>(_ buffer: [UInt8], offset: Int = 0, bigEndian: Bool = true) -> T? {
        var res: T = T.zero
        let size = MemoryLayout.size(ofValue: res)
        if (buffer.isEmpty || offset < 0 || offset + size > buffer.count) {
            return nil
        }
        var bitOffset = 0
        if (bigEndian) {
            for i in 0...size - 1 {
                bitOffset = 8 * (size - 1 - i)
                res += T(buffer[offset + i]) << bitOffset
            }
        } else {
            for i in 0...size - 1 {
                bitOffset = 8 * i
                res += T(buffer[offset + i]) << bitOffset
            }
        }
        return res
    }
}
