//
//  WDVError.swift
//  SwWidevine
//
//  Created by developer on 08.07.2024.
//

import Foundation

public enum WDVError {
    
    ///General-purpose error
    case general(errCode: Int, description: String)
    ///Cryptography error
    case cryptographyFail(description: String)
    ///Too many active sessions
    case tooManySessions(maxCount: UInt8)
    ///Not found session by ID
    case sessionNotFound(hexSessionId: String)
    ///Not found session context by request ID
    case sessionContextNotFound(ctxReqID: [UInt8], hexSessionId: String)
    ///Invalid or empty PSSH init data
    case invalidPsshInitData(_ psshInitData: Data)
    ///Invalid license type key
    case invalidLicenseType(_ typeKey: String)
    ///Invalid license message content
    case invalidLicenseMessage(_ licMsg: Data)
    ///Invalid session context
    case invalidSessionContext(_ ctx: [UInt8])
    ///License type mismatch
    case messageTypeMismatch(expected: WDVSignedMessage.MessageType, actual: String)
    ///Signature check fail
    case signatureMismatch(expected: [UInt8], actual: [UInt8])
    ///Session has no keys error
    case noSessionKeys
    ///License response message has no key containers
    case noLicenseKeyContainers(_ licMsg: Data)
    ///CDM and API device mismatch error
    case deviceMismatch(expectedDevice: Data, actualDevice: Data)
}

extension WDVError: Error {
    ///General error code, if status code is unknown or can't be retrieved
    public static let GeneralErrCode: Int = -1
    
    public var errorDescription: String {
        switch(self) {
        case .general(let errCode, let desc): return "General error - " + String(errCode) + ". Details: " + desc
        case .cryptographyFail(let description): return "Cyptography error: " + description
        case .tooManySessions(let maxCount): return "Too many active sessions are open (Max count is " + String(maxCount) + "). Try to close the old ones"
        case .sessionNotFound(let hexSessionId): return "Not found any sessions with the specified identifier '" + hexSessionId + "'"
        case .sessionContextNotFound(let ctxReqID, let hexSessionId): return "Not found context with request ID '" + WDVBase16.encode(ctxReqID) + "' at session '" + hexSessionId + "'"
        case .invalidPsshInitData(let psshInitData): return "The Widevine PSSH init data (" + String(psshInitData.count) + " bytes) is invalid"
        case .invalidLicenseType(let typeKey): return "License type key '" + typeKey + "' is invalid'"
        case .invalidLicenseMessage(let licMsg): return "The Widevine license message data (" + String(licMsg.count) + " bytes) is invalid"
        case .invalidSessionContext(let ctx): return "Provided session context (" + String(ctx.count) + " bytes) is invalid"
        case .messageTypeMismatch(let expected, let actual): return "Expected '" + String(describing: expected) + "' message type, but was '" + actual + "'"
        case .signatureMismatch: return "Signature check fail"
        case .noSessionKeys: return "No license was parsed for this Session, no keys available"
        case .noLicenseKeyContainers(let licMsg): return "Widevine license response message (" + String(licMsg.count) + " bytes) has no key containers"
        case .deviceMismatch: return "The Remote CDMs Device information and the APIs Device information did not match"
        }
    }
}
