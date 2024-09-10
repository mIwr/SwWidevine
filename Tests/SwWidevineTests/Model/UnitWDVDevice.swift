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
    
    func testDeviceParse2() {
        guard let url = TestConstants.testBundle.url(forResource: "deviceClID", withExtension: "protobuf") else {
            XCTAssertNotNil(nil, "Protobuf asset not found")
            return
        }
        let deviceClientIDBlob = (try? Data(contentsOf: url)) ?? Data()
        let device = WDVDevice.from(devicePemPrivateKey: TestConstants.defaultWdvDevicePemPrivateKey, deviceClientIDBlob: deviceClientIDBlob, platform: .Android, securityLevel: .L1)
        XCTAssertNotNil(device, "Invalid WDV device parser")
    }
    
    func testDeviceSerialize() {
        guard let safeWdvData = Data(base64Encoded: TestConstants.defaultWdvDevice) else {
            return
        }
        let bytes = [UInt8].init(safeWdvData)
        let device = WDVDevice.from(wdvBytes: bytes)
        XCTAssertNotNil(device, "Invalid WDV device parser")
        let serialized = device?.serialize() ?? []
        let device2 = WDVDevice.from(wdvBytes: serialized)
        XCTAssertNotNil(device2, "Invalid WDV device serializer")
        XCTAssertEqual(device?.version, device2?.version, "Invalid WDV device serializer")
        XCTAssertEqual(device?.platform, device2?.platform, "Invalid WDV device serializer")
        XCTAssertEqual(device?.securityLvl, device2?.securityLvl, "Invalid WDV device serializer")
        XCTAssertEqual(device?.securityLvl, device2?.securityLvl, "Invalid WDV device serializer")
        XCTAssertEqual(device?.key, device2?.key, "Invalid WDV device serializer")
        XCTAssertEqual(device?.clID.token, device2?.clID.token, "Invalid WDV device serializer")
    }
    
    func testDeviceConvertToWdvBytes() {
        guard let url = TestConstants.testBundle.url(forResource: "deviceClID", withExtension: "protobuf") else {
            XCTAssertNotNil(nil, "Protobuf asset not found")
            return
        }
        let deviceClientIDBlob = (try? Data(contentsOf: url)) ?? Data()
        let device = WDVDevice.from(devicePemPrivateKey: TestConstants.defaultWdvDevicePemPrivateKey, deviceClientIDBlob: deviceClientIDBlob, platform: .Android, securityLevel: .L1)
        XCTAssertNotNil(device, "Invalid WDV device parser")
        let serialized = device?.serialize() ?? []
        let device2 = WDVDevice.from(wdvBytes: serialized)
        XCTAssertNotNil(device2, "Invalid WDV device converter or serializer")
        XCTAssertEqual(device?.version, device2?.version, "Invalid WDV device converter or serializer")
        XCTAssertEqual(device?.platform, device2?.platform, "Invalid WDV device converter or serializer")
        XCTAssertEqual(device?.securityLvl, device2?.securityLvl, "Invalid WDV device converter or serializer")
        XCTAssertEqual(device?.securityLvl, device2?.securityLvl, "Invalid WDV device converter or serializer")
        XCTAssertEqual(device?.key, device2?.key, "Invalid WDV device converter or serializer")
        XCTAssertEqual(device?.clID.token, device2?.clID.token, "Invalid WDV device converter or serializer")
    }
}
