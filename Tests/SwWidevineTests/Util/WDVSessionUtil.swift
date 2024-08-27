//
//  WDVSessionUtil.swift
//  Wdv-Tests
//
//  Created by developer on 15.08.2024.
//

import Foundation
@testable import SwWidevine

final class WDVSessionUtil {
    
    fileprivate init() {}
    
    ///Generates Widevine session with license chanllenge context for further license response parsing
    static func generateSessionFromLicChallengeRequest(_ request: WDVLicenseRequest, appCert: WDVSignedDrmCertificate) -> WDVSession {
        let safeSerializedLicReq = (try? request.serializedData()) ?? Data()
        let sessionContext: [[UInt8]: Data] = [
            [UInt8].init(request.contentID.widevinePsshData.requestID): safeSerializedLicReq
        ]
        
        return WDVSession(number: 1, certificate: appCert, context: sessionContext, keys: [])
    }
}
