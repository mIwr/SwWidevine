//
//  CryptoUtil.swift
//  SwPSSH
//
//  Created by Developer on 07.09.2023.
//

import Foundation
#if canImport(CommonCrypto)
import CommonCrypto //SwiftPM can't import it
#else
import CryptoSwift
#endif

final class WDVCryptoUtil {
    
    fileprivate init() {}
    
    #if canImport(CommonCrypto)
    static func hmacSha256(key: [UInt8], msg: [UInt8]) -> [UInt8] {
        let msgData = Data(msg)
        let keyData = Data(key)
        var hmacData = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        let hmacStatus = hmacData.withUnsafeMutableBytes{ hmacPtr in
            guard let hmacAddr = hmacPtr.baseAddress else {return kCCParamError}
            let hmacBuffPtr: UnsafeMutablePointer<UInt8> = hmacAddr.assumingMemoryBound(to: UInt8.self)
            let hmacRawPtr = UnsafeMutableRawPointer(hmacBuffPtr)
            return msgData.withUnsafeBytes { msgPtr in
                guard let msgAddr = msgPtr.baseAddress else {return kCCParamError}
                let msgBuffPtr: UnsafePointer<UInt8> = msgAddr.assumingMemoryBound(to: UInt8.self)
                let msgRawPtr = UnsafeRawPointer(msgBuffPtr)
                return keyData.withUnsafeBytes { keyPtr in
                    guard let keyAddr = keyPtr.baseAddress else {return kCCParamError}
                    let keyBuffPtr: UnsafePointer<UInt8> = keyAddr.assumingMemoryBound(to: UInt8.self)
                    let keyRawPtr = UnsafeRawPointer(keyBuffPtr)
                    CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256), keyRawPtr, key.count, msgRawPtr, msg.count, hmacRawPtr)
                    return kCCSuccess
                }
            }
        }
        if (Int(hmacStatus) != kCCSuccess) {
            print("HMAC-SHA256 error: \(hmacStatus)")
        }

        return [UInt8].init(hmacData)
    }
    #else
    static func hmacSha256(key: [UInt8], msg: [UInt8]) -> [UInt8] {
        do {
            let hmacEng = HMAC(key: key, variant: .sha2(.sha256))
            return try hmacEng.authenticate(msg)
        } catch {
#if DEBUG
            print(error)
#endif
        }
        return []
    }
    #endif
    static func hmacSha256String(key: [UInt8], msg: [UInt8]) -> String {
        let digest = hmacSha256(key: key, msg: msg)
        var digestHex = ""
        for index in 0..<Int(digest.count) {
            digestHex += String(format: "%02x", digest[index])
        }
        return digestHex
    }
    
#if canImport(CommonCrypto)
    static func aesCbcEncrypt(msg: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        return aesCbc(operation: CCOperation(kCCEncrypt), options: CCOptions(kCCOptionPKCS7Padding), msg: msg, key: key, iv: iv)
    }
    
    static func aesCbcDecrypt(msg: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        return aesCbc(operation: CCOperation(kCCDecrypt), options: CCOptions(kCCOptionPKCS7Padding), msg: msg, key: key, iv: iv)
    }
    
    static func aesCbcNoPaddingEncrypt(msg: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        return aesCbc(operation: CCOperation(kCCEncrypt), options: CCOptions(), msg: msg, key: key, iv: iv)
    }
    
    fileprivate static func aesCbc(operation: CCOperation, options: CCOptions, msg: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        let msgData = Data(msg)
        let keyData = Data(key)
        var keySize: size_t = kCCKeySizeAES128
        if (key.count >= 32) {
            keySize = kCCKeySizeAES256
        } else if (key.count >= 24) {
            keySize = kCCKeySizeAES192
        }
        var cryptData = Data(count: msg.count + kCCBlockSizeAES128)
        let cryptDataCount = cryptData.count
        var numBytesEncrypted: size_t = 0
        let cryptStatus = cryptData.withUnsafeMutableBytes{ encryptedPtr in
            guard let encAddr = encryptedPtr.baseAddress else {return CCCryptorStatus(kCCParamError)}
            let encBuffPtr: UnsafeMutablePointer<UInt8> = encAddr.assumingMemoryBound(to: UInt8.self)
            let encryptedRawPtr = UnsafeMutableRawPointer(encBuffPtr)
            return msgData.withUnsafeBytes { msgPtr in
                guard let msgAddr = msgPtr.baseAddress else {return CCCryptorStatus(kCCParamError)}
                let msgBuffPtr: UnsafePointer<UInt8> = msgAddr.assumingMemoryBound(to: UInt8.self)
                let msgRawPtr = UnsafeRawPointer(msgBuffPtr)
                let ivData = Data(iv)
                return ivData.withUnsafeBytes { ivPtr in
                    guard let ivAddr = ivPtr.baseAddress else {return CCCryptorStatus(kCCParamError)}
                    let ivBuffPtr: UnsafePointer<UInt8> = ivAddr.assumingMemoryBound(to: UInt8.self)
                    let ivRawPtr = UnsafeRawPointer(ivBuffPtr)
                    return keyData.withUnsafeBytes { keyPtr in
                        guard let keyAddr = keyPtr.baseAddress else {return CCCryptorStatus(kCCParamError)}
                        let keyBuffPtr: UnsafePointer<UInt8> = keyAddr.assumingMemoryBound(to: UInt8.self)
                        let keyRawPtr = UnsafeRawPointer(keyBuffPtr)
                        return CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), options, keyRawPtr, keySize, ivRawPtr, msgRawPtr, msgData.count, encryptedRawPtr, cryptDataCount, &numBytesEncrypted)
                    }
                }
            }
        }
        if (Int(cryptStatus) == kCCSuccess) {
            cryptData.removeSubrange(numBytesEncrypted..<cryptData.count)
        } else {
            print("AES-CBC error: \(cryptStatus)")
        }

        return [UInt8].init(cryptData)
    }
#else
    static func aesCbcEncrypt(msg: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        do {
            let aesEng = try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
            let enc = try aesEng.encrypt(msg)
            return enc
        } catch {
            print(error)
        }
        return []
    }
    
    static func aesCbcDecrypt(msg: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        do {
            let aesEng = try AES(key: key, blockMode: CBC(iv: iv), padding: .pkcs7)
            let enc = try aesEng.decrypt(msg)
            return enc
        } catch {
            print(error)
        }
        return []
    }
    
    static func aesCbcNoPaddingEncrypt(msg: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8] {
        do {
            let aesEng = try AES(key: key, blockMode: CBC(iv: iv), padding: .noPadding)
            let enc = try aesEng.encrypt(msg)
            return enc
        } catch {
            print(error)
        }
        return []
    }
#endif
    
    #if canImport(CommonCrypto)

    static func aesCmac(msg: [UInt8], key: [UInt8]) -> [UInt8] {
        let cmacEng = WDVCMAC(key: key)
        return cmacEng.authenticate(msg)
    }
    #else
    static func aesCmac(msg: [UInt8], key: [UInt8]) -> [UInt8] {
        do {
            let cmacEng = try CMAC(key: key)
            return try cmacEng.authenticate(msg)
        } catch {
            print(error)
        }
        return []
    }
    #endif
}
