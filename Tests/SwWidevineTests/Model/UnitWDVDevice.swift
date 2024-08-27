//
//  UnitWDVDevice.swift
//  Wdv-Tests
//
//  Created by developer on 10.08.2024.
//

import XCTest
@testable import SwWidevine

final class UnitWDVDevice: XCTestCase {
    
    func testDeviceParse() {
        guard let safeWdvData = Data(base64Encoded: TestConstants.defaultWdvDevice) else {
            return
        }
        let bytes = [UInt8].init(safeWdvData)
        let device = WDVDevice.from(wdvBytes: bytes)
        XCTAssertNotNil(device, "Invalid WDV device parser")
    }
}
