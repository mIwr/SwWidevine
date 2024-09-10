//
//  WDVCDMDevice.swift
//  SwWidevine
//
//  Created by developer on 12.07.2024.
//

import Foundation
import SwiftRSA

///Widevine device info
public class WDVDevice {
    
    static let minSize: UInt8 = 11
    static let magic: [UInt8] = [ 0x57, 0x56, 0x44 ]
    
    ///Device info version
    public let version: UInt8
    ///Device platform type
    public let platform: WDVDevicePlatform
    ///Device used security level
    public let securityLvl: WDVSecurityLevel
    ///Extra bit-flags
    public let flags: UInt8
    ///Device private key (DER)
    public let key: [UInt8]
    ///Device client ID
    public let clID: WDVClientIdentification
    ///File Hashes for Verified Media Path (VMP) support
    public let vmp: WDVFileHashes
    
    ///Device private key (PEM)
    public var pemKey: String {
        get {
            var res = ""
            do {
                let rsaKey = try RSAPrivateKey(der: key, format: .X509)
                res = rsaKey.pemEncoded(format: .X509)
            } catch {
                #if DEBUG
                print(error)
                #endif
            }
            return res
        }
    }
    
    public init(version: UInt8, platform: WDVDevicePlatform, securityLvl: WDVSecurityLevel, flags: UInt8, key: [UInt8], clID: WDVClientIdentification, vmp: WDVFileHashes) {
        self.version = version
        self.platform = platform
        self.securityLvl = securityLvl
        self.flags = flags
        self.key = key
        self.clID = clID
        self.vmp = vmp
    }
    
    ///Serializes device info as wvd file bytes
    public func serialize() -> [UInt8] {
        var wdvBytes = [UInt8].init(WDVDevice.magic)
        wdvBytes.append(version)
        wdvBytes.append(platform.rawValue)
        wdvBytes.append(securityLvl.rawValue)
        wdvBytes.append(flags)
        wdvBytes.append(contentsOf: WDVBinaryUtil.getBytes(UInt16(key.count)))
        wdvBytes.append(contentsOf: key)
        var data = Data()
        do {
            data = try clID.serializedData()
        } catch {
            #if DEBUG
            print(error)
            #endif
        }
        wdvBytes.append(contentsOf: WDVBinaryUtil.getBytes(UInt16(data.count)))
        wdvBytes.append(contentsOf: data)
        if (version == 1) {
            data = Data()
            do {
                data = try vmp.serializedData()
            } catch {
                #if DEBUG
                print(error)
                #endif
            }
            wdvBytes.append(contentsOf: WDVBinaryUtil.getBytes(UInt16(data.count)))
            wdvBytes.append(contentsOf: data)
        }
        return wdvBytes
    }
    
    public static func from(b64WdvDeviceData: String) -> WDVDevice? {
        guard let safeWdvData = Data(base64Encoded: b64WdvDeviceData) else {
            #if DEBUG
            print("Invalid Base64-encoded WDV device (" + String(b64WdvDeviceData.count) + " bytes)")
            #endif
            return nil
        }
        return from(wdvBytes: [UInt8].init(safeWdvData))
    }
    
    public static func from(devicePemPrivateKey: String, deviceClientIDBlob: Data, platform: WDVDevicePlatform, securityLevel: WDVSecurityLevel, deviceInfoVersion: UInt8 = 2, flags: UInt8 = 0) -> WDVDevice? {
        let rsaKey: RSAPrivateKey
        do {
            rsaKey = try RSAPrivateKey(pem: devicePemPrivateKey, format: .X509)
        } catch {
            #if DEBUG
            print(error)
            #endif
            return nil
        }
        let clID: WDVClientIdentification
        do {
            clID = try WDVClientIdentification(serializedBytes: deviceClientIDBlob)
        } catch {
            #if DEBUG
            print(error)
            #endif
            return nil
        }
        var vmp = WDVFileHashes()
        var safeVersion = deviceInfoVersion
        do {
            vmp = try WDVFileHashes(serializedBytes: clID.vmpData)
            safeVersion = 2
        } catch {
            #if DEBUG
            print(error)
            #endif
        }
        return WDVDevice(version: safeVersion, platform: platform, securityLvl: securityLevel, flags: flags, key: rsaKey.derEncoded(format: .X509), clID: clID, vmp: vmp)
    }
    
    public static func from(wdvBytes: [UInt8]) -> WDVDevice? {
        if (wdvBytes.count < WDVDevice.minSize || wdvBytes[0] != WDVDevice.magic[0] || wdvBytes[1] != WDVDevice.magic[1] || wdvBytes[2] != WDVDevice.magic[2]) {
            print("Error: Invalid WDV data - Not found MAGIC header")
            return nil
        }
        var offset = 3
        let version: UInt8 = WDVBinaryUtil.getVal(wdvBytes, offset: offset) ?? 1
        offset += 1
        let typeKey: UInt8 = WDVBinaryUtil.getVal(wdvBytes, offset: offset) ?? 0
        offset += 1
        let type = WDVDevicePlatform(rawValue: typeKey) ?? WDVDevicePlatform.Android
        let securityLevelKey: UInt8 = WDVBinaryUtil.getVal(wdvBytes, offset: offset) ?? 3
        offset += 1
        let securityLvl = WDVSecurityLevel(rawValue: securityLevelKey) ?? WDVSecurityLevel.L3
        let flags: UInt8 = WDVBinaryUtil.getVal(wdvBytes, offset: offset) ?? 0
        offset += 1
        var len: UInt16 = WDVBinaryUtil.getVal(wdvBytes, offset: offset) ?? 0
        offset += 2
        let pKey = [UInt8].init(wdvBytes[offset...offset + Int(len - 1)])
        offset += Int(len)
        len = WDVBinaryUtil.getVal(wdvBytes, offset: offset) ?? 0
        offset += 2
        var buff = [UInt8].init(wdvBytes[offset...offset + Int(len - 1)])
        guard let safeClID = try? WDVClientIdentification(serializedBytes: buff) else {
            print("Error: Unable to parse WDVClientIdentification from raw (" + String(buff.count) + ")")
            return nil
        }
        offset += Int(len)
        buff = []
        if (version == 1 && offset + 2 < wdvBytes.count) {
            //VMP exists only for version 1
            len = WDVBinaryUtil.getVal(wdvBytes, offset: offset) ?? 0
            if (len > 0) {
                buff = [UInt8].init(wdvBytes[offset...offset + Int(len - 1)])
            }
            offset += Int(len)
        }
        if (buff.isEmpty && version == 2) {
            //Removed vmp and vmp_len as it should already be within the Client ID
            buff = [UInt8].init(safeClID.vmpData)
        }
        guard let safeVmp = try? WDVFileHashes(serializedBytes: buff) else {
            print("Error: Unable to parse WDVFileHashes from raw (" + String(buff.count) + ")")
            return nil
        }
        if (wdvBytes.count > offset) {
            print("Warning: read position isn't at the end (" + String(offset) + "/" + String(wdvBytes.count) + ") . Possible the new data on protobuf")
        }
        return WDVDevice(version: version, platform: type, securityLvl: securityLvl, flags: flags, key: pKey, clID: safeClID, vmp: safeVmp)
    }
}
