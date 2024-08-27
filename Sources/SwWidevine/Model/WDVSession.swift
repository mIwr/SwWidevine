//
//  WDVSession.swift
//  SwWidevine
//
//  Created by developer on 04.06.2024.
//

import Foundation

///Widevine session
public class WDVSession {
    
    fileprivate static let _encLblBytes: [UInt8] = [0x45, 0x4E, 0x43, 0x52, 0x59, 0x50, 0x54, 0x49, 0x4F, 0x4E]//ENCRYPTION
    fileprivate static let _authLblBytes: [UInt8] = [0x41, 0x55, 0x54, 0x48, 0x45, 0x4E, 0x54, 0x49, 0x43, 0x41, 0x54, 0x49, 0x4F, 0x4E]//AUTHENTICATION
    fileprivate static let _idSize: UInt8 = 16
    
    ///Session sequence number
    public let number: Int64
    ///Session ID
    public let id: [UInt8]
    ///Session ID hex-string
    public var hexId: String {
        get {
            return WDVBase16.encode(id)
        }
    }
    ///DRM application certificate (Privacy certificate)
    public let certificate: WDVSignedDrmCertificate?
    ///DRM license message requests
    public let context: [[UInt8]: Data]
    ///DRM content keys
    public let keys: [WDVKey]
    
    public init(number: Int64, id: [UInt8]? = nil, certificate: WDVSignedDrmCertificate? = nil, context: [[UInt8]: Data] = [:], keys: [WDVKey] = []) {
        self.number = number
        if let safeId = id, safeId.count == WDVSession._idSize {
            self.id = safeId
        } else {
            var arr = [UInt8].init(repeating: 0, count: Int(WDVSession._idSize))
            for i in 0...arr.count - 1 {
                arr[i] = UInt8.random(in: 0...UInt8.max)
            }
            self.id = arr
        }
        self.certificate = certificate
        self.context = context
        self.keys = keys
    }
    
    func generateEncContext(licMsgRequestID: [UInt8]) -> [UInt8]? {
        guard let safeLicMsgRequest = context[licMsgRequestID] else {
            return nil
        }
        return WDVSession.generateEncContext(licMsgRequest: safeLicMsgRequest)
    }
    
    func generateMacContext(licMsgRequestID: [UInt8]) -> [UInt8]? {
        guard let safeLicMsgRequest = context[licMsgRequestID] else {
            return nil
        }
        return WDVSession.generateMacContext(licMsgRequest: safeLicMsgRequest)
    }
    
    ///Returns 2 Context Data used for computing the AES Encryption and HMAC Keys.
    static func deriveContext(licMsgRequest: Data) -> ([UInt8],[UInt8]) {
        return (WDVSession.generateEncContext(licMsgRequest: licMsgRequest), WDVSession.generateMacContext(licMsgRequest: licMsgRequest))
    }
    
    static func generateEncContext(licMsgRequest: Data) -> [UInt8] {
        let keySizeInBits: Int32 = 128//16 * 8
        var encContext: [UInt8] = []//"ENCRYPTION" + b"\x00" + msg + key_size.to_bytes(4, "big")
        encContext.append(contentsOf: WDVSession._encLblBytes)
        encContext.append(0)
        encContext.append(contentsOf: licMsgRequest)
        encContext.append(contentsOf: WDVBinaryUtil.getBytes(keySizeInBits, bigEndian: true))
        return encContext
    }
    
    static func generateMacContext(licMsgRequest: Data) -> [UInt8] {
        let keySizeInBits: Int32 = 512//32 * 8 * 2
        var macContext: [UInt8] = []//"AUTHENTICATION" + b"\x00" + msg + key_size.to_bytes(4, "big")
        macContext.append(contentsOf: WDVSession._authLblBytes)
        macContext.append(0)
        macContext.append(contentsOf: licMsgRequest)
        macContext.append(contentsOf: WDVBinaryUtil.getBytes(keySizeInBits, bigEndian: true))
        return macContext
    }
}
