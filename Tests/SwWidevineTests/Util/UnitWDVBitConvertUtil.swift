//
//  UnitBitConvertUtil.swift
//  SwWidevine
//
//  Created by Developer on 09.08.2024.
//

import Foundation

import XCTest
@testable import SwWidevine

class UnitWDVBitConvertUtil: XCTestCase {
    
    func testConvertToInt16() {
        let buff: [UInt8] = [0x10, 0x11, 0x12, 0x13]
        
        let converted: Int16? = WDVBinaryUtil.getVal(buff, offset: 1, bigEndian: true)
        XCTAssertEqual(converted, 4370, "Incorrect convert process")
    }
    
    func testConvertToInt64() {
        let buff: [UInt8] = [0x95, 0x60, 0x18, 0x90, 0xAF, 0xD8, 0x7, 0x9]
        
        let converted: Int64? = WDVBinaryUtil.getVal(buff, bigEndian: true)
        XCTAssertEqual(converted, -7683113954589538551, "Incorrect convert process")
    }
    
    func testGetBytesFromInt32() {
        let val: Int32 = 269554195
        let buff: [UInt8] = [0x10, 0x11, 0x12, 0x13]
        let bytes = WDVBinaryUtil.getBytes(val)
        XCTAssertEqual(bytes, buff, "Incorrect convert process")
    }
}
