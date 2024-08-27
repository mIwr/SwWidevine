//
//  WdvKey.swift
//  SwWidevine
//
//  Created by developer on 04.06.2024.
//

import Foundation

///Widevine DRM key
public class WDVKey {
    
    public static let keyIDSize: UInt8 = 16
    
    ///Key ID (kid)
    public let id: [UInt8]
    public var hexID: String {
        get {
            return WDVBase16.encode(id)
        }
    }
    ///Key type
    public let type: String
    ///Key bytes
    public let data: [UInt8]
    public var hexData: String {
        get {
            return WDVBase16.encode(data)
        }
    }
    ///Key operation permissions
    public let permissions: Set<String>
    ///Content key has encryption permission
    public var canEncrypt: Bool {
        get {
            return permissions.contains("allowEncrypt")
        }
    }
    ///Key has decryption permission
    public var canDecrypt: Bool {
        get {
            return permissions.contains("allowDecrypt")
        }
    }
    ///Key has signature permission
    public var canSign: Bool {
        get {
            return permissions.contains("allowSign")
        }
    }
    ///Key has signature verify permission
    public var allowEncrypt: Bool {
        get {
            return permissions.contains("allowSignatureVerify")
        }
    }
    
    public init(id: [UInt8], type: String, data: [UInt8], permissions: Set<String> = []) {
        self.id = id
        self.type = type
        self.data = data
        self.permissions = permissions
    }
    
    /// Convert a Key ID from a string or bytes to a UUID object. At first this may seem very simple but some types of Key IDs may not be 16 bytes and some may be decimal vs. hex.
    static func parseKeyID(keyID: String) -> [UInt8]? {
        guard let safeRes = Data(base64Encoded: keyID) else {return nil}
        return parseKeyID(keyIDBytes: safeRes)
    }
    
    /// Convert a Key ID from a string or bytes to a UUID object. At first this may seem very simple but some types of Key IDs may not be 16 bytes and some may be decimal vs. hex.
    static func parseKeyID(keyIDBytes: Data) -> [UInt8] {
        var bytes = [UInt8].init(keyIDBytes)
        if (bytes.count < keyIDSize) {
            let deltaCount = Int(keyIDSize) - bytes.count
            bytes.insert(contentsOf: [UInt8].init(repeating: 0, count: deltaCount), at: 0)
        }
        return bytes
    }
    
    ///Load Key from a KeyContainer object
    static func from(protobuf: WDVLicense.KeyContainer, key: [UInt8]) -> Result<WDVKey, WDVError> {
        var permissions: Set<String> = []
        if (protobuf.type == .operatorSession) {
            if (protobuf.operatorSessionKeyPermissions.allowEncrypt) {
                permissions.insert(String(describing: protobuf.operatorSessionKeyPermissions.allowEncrypt))
            }
            if (protobuf.operatorSessionKeyPermissions.allowDecrypt) {
                permissions.insert(String(describing: protobuf.operatorSessionKeyPermissions.allowDecrypt))
            }
            if (protobuf.operatorSessionKeyPermissions.allowSign) {
                permissions.insert(String(describing: protobuf.operatorSessionKeyPermissions.allowSign))
            }
            if (protobuf.operatorSessionKeyPermissions.allowSignatureVerify) {
                permissions.insert(String(describing: protobuf.operatorSessionKeyPermissions.allowSignatureVerify))
            }
        }
        let decoded = WDVCryptoUtil.aesCbcDecrypt(msg: [UInt8].init(protobuf.key), key: key, iv: [UInt8].init(protobuf.iv))
        if (decoded.isEmpty) {
            return .failure(.cryptographyFail(description: "Content key decryption with AES-CBC fail"))
        }
        /*do {
            let encKeyData = [UInt8].init(protobuf.key)
            let ivData = [UInt8].init(protobuf.iv)
            let aesEng = try AES(key: key, blockMode: CBC(iv: ivData), padding: .pkcs7)
            //key = Padding.unpad(AES.new(enc_key, AES.MODE_CBC, iv=key.iv).decrypt(key.key),16),
            decoded =  try aesEng.decrypt(encKeyData)
        } catch {
            #if DEBUG
            print(error)
            #endif
            return .failure(.cryptographyFail(description: "Content key decryption with AES-CBC fail: " + error.localizedDescription))
        }*/
        return .success(WDVKey(id: WDVKey.parseKeyID(keyIDBytes: protobuf.id), type: String(describing: protobuf.type), data: decoded, permissions: permissions))
    }
}
