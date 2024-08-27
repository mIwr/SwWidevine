//
//  UnitStringUtilTest.swift
//  SwWidevine
//
//  Created by Developer on 09.08.2024.
//

import XCTest
@testable import SwWidevine

final class UnitWDVBase16: XCTestCase {
    
    func testBytesToHexString() {
        let buff:[UInt8] = [0x7, 0xdf, 0x23, 0xa0, 0xC, 0x56]
        let str = WDVBase16.encode(buff)
        XCTAssertEqual(str, "07df23a00c56", "Incorrect bytes to hex convert")
    }
    
    func testHexStringToBytes() {
        let str = "7df23a00c56"
        let buff = WDVBase16.decode(str)
        let expected:[UInt8] = [0x7, 0xdf, 0x23, 0xa0, 0xC, 0x56]
        XCTAssertEqual(expected, buff, "Incorrect hex to bytes convert")
    }
}
