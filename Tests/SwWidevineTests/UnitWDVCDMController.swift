//
//  UnitWDVCDMController.swift
//  Wdv-Tests
//
//  Created by developer on 10.08.2024.
//

import XCTest
@testable import SwWidevine
import SwPSSH

final class UnitWDVCDMController: XCTestCase  {
    
    fileprivate var _serviceCert: WDVSignedDrmCertificate?
    fileprivate var _controller: WDVCDMController?
    
    override func setUp() {
        super.setUp()
        var wdvData = Data(base64Encoded: TestConstants.defaultWdvDevice) ?? Data()
        guard let safeDevice = WDVDevice.from(wdvBytes: [UInt8].init(wdvData)) else {
            return
        }
        _controller = try? WDVCDMController(device: safeDevice)
        guard let url = TestConstants.testBundle.url(forResource: "appCrt", withExtension: "protobuf") else {
            return
        }
        wdvData = (try? Data(contentsOf: url)) ?? Data()
        guard let safeCert = try? WDVSignedDrmCertificate(serializedBytes: wdvData) else {
            return
        }
        _serviceCert = safeCert
    }
    
    func testLicMsgRequestParse() {
        guard let url = TestConstants.testBundle.url(forResource: "licRequest", withExtension: "protobuf") else {
            XCTAssertNotNil(nil, "Protobuf asset not found")
            return
        }
        let data = (try? Data(contentsOf: url)) ?? Data()
        let signedMsg = try? WDVSignedMessage(serializedBytes: data)
        XCTAssertNotNil(signedMsg, "License message request is nil")
        let licReq = try? WDVLicenseRequest(serializedBytes: signedMsg?.msg ?? Data())
        XCTAssertNotNil(licReq, "License request is nil")
    }
    
    func testLicMsgResponseParse() {
        guard let url = TestConstants.testBundle.url(forResource: "licResponse", withExtension: "protobuf") else {
            XCTAssertNotNil(nil, "Protobuf asset not found")
            return
        }
        let data = (try? Data(contentsOf: url)) ?? Data()
        let signedMsg = try? WDVSignedMessage(serializedBytes: data)
        XCTAssertNotNil(signedMsg, "License message response is nil")
        let license = try? WDVLicense(serializedBytes: signedMsg?.msg ?? Data())
        XCTAssertNotNil(license, "License message payload is nil")
    }
    
    func testLicChallengeGenerator() {
        guard let safePssh = PSSHBox.from(b64EncodedBox: TestConstants.psshEncoded) else {
            XCTAssertTrue(false, "Invalid PSSH parser")
            return
        }
        let openRes = _controller?.openNewSession(serviceCertificate: _serviceCert)
        guard let safeSession = (try? openRes?.get()) else {
            XCTAssertTrue(false, "Invalid WDV CDM session ctor")
            return
        }
        let challengeRes = _controller?.generateLicChallenge(sessionHexId: safeSession.hexId, pssh: safePssh, licenseType: .streaming, privacyMode: true)
        _ = _controller?.closeSession(sessionHexId: safeSession.hexId)
        guard let safeChallengeBytes = (try? challengeRes?.get()) else {
            XCTAssertTrue(false, "Invalid WDV CDM License challenge generator")
            return
        }
        XCTAssertGreaterThan(safeChallengeBytes.count, 0, "Invalid WDV CDM License challenge generator - Empty")
    }
    
    func testLicResponseParser() {
        guard let safeServiceCert = _serviceCert else {
            XCTAssertNotNil(nil, "Widevine CDM privacy certificate is nil")
            return
        }
        guard let url = TestConstants.testBundle.url(forResource: "licReqSelfGenerated", withExtension: "protobuf") else {
            XCTAssertNotNil(nil, "Protobuf asset not found")
            return
        }
        var data = (try? Data(contentsOf: url)) ?? Data()
        guard let signedMsg = try? WDVSignedMessage(serializedBytes: data) else {
            XCTAssertNotNil(nil, "Signed license message request is nil")
            return
        }
        guard let licReq = try? WDVLicenseRequest(serializedBytes: signedMsg.msg) else {
            XCTAssertNotNil(nil, "License message request is nil")
            return
        }
        guard let responseUrl = TestConstants.testBundle.url(forResource: "licRespBySelfGenerated", withExtension: "protobuf") else {
            XCTAssertNotNil(nil, "Protobuf asset not found")
            return
        }
        data = (try? Data(contentsOf: responseUrl)) ?? Data()
        let rebuiltSession = WDVSessionUtil.generateSessionFromLicChallengeRequest(licReq, appCert: safeServiceCert)
        _controller?.setSession(rebuiltSession)
        let extractRes = _controller?.extractKeyFromLicenseMsg(sessionHexId: rebuiltSession.hexId, licSrvResponse: data)
        guard let safeContentKeys = (try? extractRes?.get()) else {
            XCTAssertTrue(false, "Invalid WDV CDM License response parser")
            return
        }
        XCTAssertGreaterThan(safeContentKeys.count, 0, "Invalid WDV CDM License response parser - Empty keys array")
        for key in safeContentKeys {
            XCTAssertGreaterThan(key.data.count, 0, "Invalid WDV CDM License response parser - Empty key data")
        }
    }
}
