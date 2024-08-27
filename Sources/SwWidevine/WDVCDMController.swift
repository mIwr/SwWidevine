//
//  WDVCDMController.swift
//  SwWidevine
//
//  Created by developer on 12.07.2024.
//

import Foundation
import SwPSSH
import SwiftRSA


//Checked: -CryptoSwift (Standalone, no OAEP/PSS support, cocoapod/spm support), -SwiftyRSA (builds only on ios), -SwCrypt (uses CC bindings), +-CryptorRSA(Standalone, PSS support, Possible no OAEP support), +-SwiftRSA[leif-ibsen/SwiftRSA](Standalone, OAEP/PSS support, no cocoapod), -+SwiftRSA[puretears/SwiftRSA](non-standalone[import Security], OAEP support, no PSS, no cocoapod), -+SwiftRSA[wuyuehyang/RSASwift](non-standalone[import Security], OAEP support, no PSS, no cocoapod/spm)

//https://github.com/tmurakam/rsa-oaep

public class WDVCDMController {
    
    public static let sessionMaxCount: UInt8 = 16
    
    fileprivate let _rsaPrvKey: RSAPrivateKey
    fileprivate var _sessions: [String: WDVSession]
    
    public let device: WDVDevice
    
    public init(device: WDVDevice) throws {
        self.device = device
        _sessions = [:]
        _rsaPrvKey = try RSAPrivateKey(der: device.key, format: .X509)
    }
    
    ///Creates the new session for Widevine CDM
    ///- Parameter serviceCertificate: DRM application certificate. Optional, but recommended for use
    ///- Returns: Result with created Widevine session or creation error
    public func openNewSession(serviceCertificate: WDVSignedDrmCertificate?) -> Result<WDVSession, WDVError> {
        if (_sessions.count >= WDVCDMController.sessionMaxCount) {
            return .failure(.tooManySessions(maxCount: WDVCDMController.sessionMaxCount))
        }
        let session = WDVSession(number: Int64(_sessions.count + 1), certificate: serviceCertificate)
        _sessions[session.hexId] = session
        return .success(session)
    }
    
    ///Searches session on controller storage
    ///- Parameter sessionHexId: Widevine CDM session ID
    ///- Returns: Widevine CDM session
    public func findSession(sessionHexId: String) -> WDVSession? {
        return _sessions[sessionHexId]
    }
    
    #if DEBUG
    ///Testing purposes only
    ///Used for pre-define session context for parsing license response
    func setSession(_ session: WDVSession) {
        _sessions[session.hexId] = session
    }
    #endif
    
    ///Removes the Widevine CDM session by ID
    ///- Parameter sessionHexId: Widevine CDM session ID
    ///- Returns: Result with deletion status
    public func closeSession(sessionHexId: String) -> Result<Bool, WDVError> {
        guard let _ = _sessions.removeValue(forKey: sessionHexId) else {
            return .failure(.sessionNotFound(hexSessionId: sessionHexId))
        }
        return .success(true)
    }
    
    ///Generates Widevine license challenge request message for sending to license server
    ///- Parameter sessionHexId: Widevine CDM session ID
    ///- Parameter pssh: Protection System Specific Header (PSSH) box container with Widevine init data
    ///- Parameter licenseType: Challenge request license type
    ///- Parameter privacyMode: Encrypts the device client ID using the session DRM application certificate (Privacy Certificate). If the privacy certificate is not set yet, this does nothing
    ///- Returns: Result with signed license challenge message
    public func generateLicChallenge(sessionHexId: String, pssh: PSSHBox, licenseType: WDVLicenseType = .streaming, privacyMode: Bool = true) -> Result<Data, WDVError> {
        guard let safeSession = _sessions[sessionHexId] else {
            return .failure(.sessionNotFound(hexSessionId: sessionHexId))
        }
        var reqID = [UInt8].init(repeating: 0, count: 16)
        for i in 0...reqID.count - 1 {
            reqID[i] = UInt8.random(in: 0...UInt8.max)
        }
        if (device.platform == .Android) {
            //OEMCrypto's request_id seems to be in AES CTR Counter block form with no suffix
            //Bytes 5-8 does not seem random, in real tests they have been consecutive \x00 or \xFF
            //Real example: A0DCE548000000000500000000000000
            for i in 0...3 {
                reqID[i] = UInt8.random(in: 0...UInt8.max)
            }
            reqID[4] = 0
            reqID[5] = 0
            reqID[6] = 0
            reqID[7] = 0
            let sessionNumberLeBytes = WDVBinaryUtil.getBytes(safeSession.number, bigEndian: false)
            var index = 8
            for leByte in sessionNumberLeBytes {
                reqID[index] = leByte
                index += 1
            }
            //as you can see in the real example, it is stored as uppercase hex and re-encoded
            //it's really 16 bytes of data, but it's stored as a 32-char HEX string (32 bytes)
            //let hexStr = WDVBase16.encode(reqID).uppercased()
            //reqID = WDVBase16.decode(hexStr)
        }
        
        var licReq = WDVLicenseRequest()
        var contentID = WDVLicenseRequest.ContentIdentification()
        var psshData = WDVLicenseRequest.ContentIdentification.WidevinePsshData()
        psshData.licenseType = licenseType
        psshData.requestID = Data(reqID)
        guard let safeInitData = pssh.initData, !safeInitData.isEmpty, pssh.widevineSystem else {
            return .failure(.invalidPsshInitData(pssh.initData ?? Data()))
        }
        psshData.psshData = [safeInitData]
        contentID.widevinePsshData = psshData
        licReq.contentID = contentID
        licReq.type = .new
        licReq.requestTime = Int64(Date().timeIntervalSince1970)
        licReq.protocolVersion = .version21
        licReq.keyControlNonce = UInt32.random(in: 1...0x80000000)//1..2^31
        if let safeCert = safeSession.certificate, privacyMode {
            let encClIDRes = WDVCDMController.encryptClientIDWithSignedCert(device.clID, safeCert)
            do {
                licReq.encryptedClientID = try encClIDRes.get()
            } catch {
                if let wdvErr = error as? WDVError {
                    return .failure(wdvErr)
                }
                return .failure(.cryptographyFail(description: "Device client ID encryption fail - " + error.localizedDescription))
            }
        } else {
            licReq.clientID = device.clID
        }
        let safeSerializedLicReq = (try? licReq.serializedData()) ?? Data()
        let safeSerializedLicReqBytes = [UInt8].init(safeSerializedLicReq)
        
        var signedLicReq = WDVSignedMessage()
        signedLicReq.type = .licenseRequest
        signedLicReq.msg = safeSerializedLicReq
        //saltLen = SHA1_DIGEST_LENGTH (Test for 'emLen - hLen - 2', emLen - RSA modulus, hLen - Hash digest length)
        let sign = try? _rsaPrvKey.signPSS(message: safeSerializedLicReqBytes, kind: .SHA1)
        signedLicReq.signature = Data(sign ?? []) //self.__signer.sign(SHA1.new(license_request))
        let safeSerializedSignedLicReq = (try? signedLicReq.serializedData()) ?? Data()
        
        var updContext = safeSession.context
        updContext[reqID] = safeSerializedLicReq
        let updSession = WDVSession(number: safeSession.number, id: safeSession.id, certificate: safeSession.certificate, context: updContext, keys: safeSession.keys)
        _sessions[sessionHexId] = updSession
        
        return .success(safeSerializedSignedLicReq)
    }
    
    ///Extracts decryption key(-s) from  raw license server response
    ///- Parameter sessionHexId: Widevine CDM session ID. Optional. If not stated, searches license request context in all opened sessions
    ///- Parameter licSrvResponse: Raw license server response
    ///- Returns: Result with extracred decryption key(-s)
    public func extractKeyFromLicenseMsg(sessionHexId: String? = nil, licSrvResponse: Data) -> Result<[WDVKey], WDVError> {
        let signedMsgResponse: WDVSignedMessage
        do {
            signedMsgResponse = try WDVSignedMessage(serializedBytes: licSrvResponse)
        } catch {
            #if DEBUG
            print(error)
            #endif
            if let safeWdvErr = error as? WDVError {
                return .failure(safeWdvErr)
            }
            return .failure(.general(errCode: -1, description: "Invalid raw license server response (" + String(licSrvResponse.count) + ": " + error.localizedDescription))
        }
        return extractKeyFromLicenseMsg(sessionHexId: sessionHexId, signedMsgResponse: signedMsgResponse)
    }

    ///Extracts decryption key(-s) from parsed license server response
    ///- Parameter sessionHexId: Widevine CDM session ID. Optional. If not stated, searches license request context in all opened sessions
    ///- Parameter signedMsgResponse: Signed license message from server
    ///- Returns: Result with extracred decryption key(-s)
    public func extractKeyFromLicenseMsg(sessionHexId: String? = nil, signedMsgResponse: WDVSignedMessage) -> Result<[WDVKey], WDVError> {
        if (signedMsgResponse.type != .license) {
            return .failure(.messageTypeMismatch(expected: .license, actual: String(describing: signedMsgResponse.type)))
        }
        let license: WDVLicense
        do {
            license = try WDVLicense(serializedBytes: signedMsgResponse.msg)
        } catch {
            #if DEBUG
            print(error)
            #endif
            return .failure(.invalidLicenseMessage(signedMsgResponse.msg))
        }
        if (license.key.isEmpty) {
            return .failure(.noLicenseKeyContainers(signedMsgResponse.msg))
        }
        let licReqID = [UInt8].init(license.id.requestID)
        var session: WDVSession?
        var licMsgRequest: Data?
        //Search by provided session ID
        if let safeSessionHexId = sessionHexId, let safeFoundSession = _sessions[safeSessionHexId], let safeFoundContext = safeFoundSession.context[licReqID] {
            session = safeFoundSession
            licMsgRequest = safeFoundContext
        }
        //Reserve search in all sessions by license request ID
        if (session == nil) {
            for s in _sessions.values {
                guard let safeFoundContext = s.context[licReqID] else {
                    continue
                }
                session = s
                licMsgRequest = safeFoundContext
                break
            }
        }
        guard let safeSession = session else {
            return .failure(.sessionNotFound(hexSessionId: sessionHexId ?? "N/A"))
        }
        guard let safeLicMsgRequest = licMsgRequest else {
            #if DEBUG
            print("Cannot parse a license message without first making a license request")
            #endif
            return .failure(.sessionContextNotFound(ctxReqID: licReqID, hexSessionId: safeSession.hexId))
        }
        let encContext = WDVSession.generateEncContext(licMsgRequest: safeLicMsgRequest)
        let macContext = WDVSession.generateMacContext(licMsgRequest: safeLicMsgRequest)
        //__decrypter.decrypt(license_message.session_key) __decrypter - PKCS1_OAEP.new(rsa_key)
        let sessionKey: [UInt8]
        do {
            sessionKey = try _rsaPrvKey.decryptOAEP(cipher: [UInt8].init(signedMsgResponse.sessionKey), kind: .SHA1)
        } catch {
            #if DEBUG
            print(error)
            #endif
            return .failure(.cryptographyFail(description: "Decrypt session key with device RSA private key fail; " + error.localizedDescription))
        }
        let encKey: [UInt8]
        let macKeySrv: [UInt8]
        //let macKeyClient: [UInt8]
        do {
            let deriveRes = WDVCDMController.deriveKeys(encContext: encContext, macContext: macContext, key: sessionKey)
            let derived = try deriveRes.get()//enc_key, mac_key_server, _ = self.derive_keys(*context,key=self.__decrypter.decrypt(license_message.session_key))
            encKey = derived.0
            macKeySrv = derived.1
            //macKeyClient = derived.2
        } catch {
            if let wdvErr = error as? WDVError {
                return .failure(wdvErr)
            }
            return .failure(.general(errCode: -1, description: "Derive keys (encKey, macKeySrv, macKeyClient) fail: " + error.localizedDescription))
        }
        //1. Explicitly use the original `license_message.msg` instead of a re-serializing from `licence` as some differences may end up in the output due to differences in the proto schema
        //2. The oemcrypto_core_message (unknown purpose) is part of the signature algorithm starting with OEM Crypto API v16 and if available, must be prefixed when HMAC'ing a signature.
                
        var msg = [UInt8].init(signedMsgResponse.oemcryptoCoreMessage)
        msg.append(contentsOf: signedMsgResponse.msg)
        let computedSignature: [UInt8] = WDVCryptoUtil.hmacSha256(key: macKeySrv, msg: msg)
        /*do {
            let hmacEng = HMAC(key: macKeySrv, variant: .sha2(.sha256))
            computedSignature = try hmacEng.authenticate(msg)
        } catch {
#if DEBUG
            print(error)
#endif
            return .failure(.cryptographyFail(description: "HMAC-SHA256 authenticate license message from server fail; " + error.localizedDescription))
        }*/
        let responseSignature = [UInt8].init(signedMsgResponse.signature)
        if (responseSignature != computedSignature) {
            return .failure(.signatureMismatch(expected: responseSignature, actual: computedSignature))
        }
        
        var keys: [WDVKey] = []
        for licKeyContainer in license.key {
            do {
                let contentKeyRes = WDVKey.from(protobuf: licKeyContainer, key: encKey)//Key.from_key_container(key, enc_key)
                keys.append(try contentKeyRes.get())
            } catch {
                if let wdvErr = error as? WDVError {
                    return .failure(wdvErr)
                }
                return .failure(.general(errCode: -1, description: "Content key parsing fail: " + error.localizedDescription))
            }
        }
        if (keys.isEmpty) {
            return .failure(.noLicenseKeyContainers(signedMsgResponse.msg))
        }
        #if DEBUG
        if (keys.count > 1) {
            print("Warning: parsed more of 1 content key (" + String(keys.count) + " keys)")
        }
        #endif
        
        
        var sessionContentKeys = [WDVKey].init(safeSession.keys)
        sessionContentKeys.append(contentsOf: keys)
        var sessionContext = safeSession.context
        sessionContext.removeValue(forKey: licReqID)//del session.context[licence.id.request_id]
        _sessions[safeSession.hexId] = WDVSession(number: safeSession.number, id: safeSession.id, certificate: safeSession.certificate, context: sessionContext, keys: sessionContentKeys)
        
        return .success(keys)
    }
    
    static func encryptClientIDWithSignedCert(_ clID: WDVClientIdentification, _ signedServiceCert: WDVSignedDrmCertificate, key: [UInt8]? = nil, iv: [UInt8]? = nil) -> Result<WDVEncryptedClientIdentification, WDVError> {
        let serviceCert = (try? WDVDrmCertificate(serializedBytes: signedServiceCert.drmCertificate)) ?? WDVDrmCertificate()
        return encryptClientID(clID, serviceCert: serviceCert, key: key, iv: iv)
    }
    
    static func encryptClientID(_ clID: WDVClientIdentification, serviceCert: WDVDrmCertificate, key: [UInt8]? = nil, iv: [UInt8]? = nil) -> Result<WDVEncryptedClientIdentification, WDVError> {
        let encKey: [UInt8]
        if let safeKey = key, safeKey.count == 16 {
            encKey = safeKey
        } else {
            var key = [UInt8].init(repeating: 0, count: 16)
            for i in 0...key.count - 1 {
                key[i] = UInt8.random(in: 0...UInt8.max)
            }
            encKey = key
        }
        var encIv: [UInt8]
        if let safeIv = iv, safeIv.count == 16 {
            encIv = safeIv
        } else {
            encIv = [UInt8].init(repeating: 0, count: 16)
            for i in 0...encIv.count - 1 {
                encIv[i] = UInt8.random(in: 0...UInt8.max)
            }
        }
        let encClIDData: Data
        do {
            
            let serializedClID = try clID.serializedData()
            let encBytes = WDVCryptoUtil.aesCbcEncrypt(msg: [UInt8].init(serializedClID), key: encKey, iv: encIv)
            if (encBytes.isEmpty) {
                return .failure(.cryptographyFail(description: "Unable to encrypt device client ID"))
            }
            /*let aesEng = try AES(key: encKey, blockMode: CBC(iv: encIv), padding: .pkcs7)
            let encBytes = try aesEng.encrypt([UInt8].init(serializedClID))//AES.new(privacy_key, AES.MODE_CBC, privacy_iv).encrypt(Padding.pad(client_id.SerializeToString(), 16))*/
            encClIDData = Data(encBytes)
        } catch {
            #if DEBUG
            print(error)
            #endif
            return .failure(.cryptographyFail(description: "Unable to encrypt device client ID; " + error.localizedDescription))
        }
        var encClID = WDVEncryptedClientIdentification()
        encClID.providerID = serviceCert.providerID
        encClID.serviceCertificateSerialNumber = serviceCert.serialNumber
        encClID.encryptedClientID = encClIDData
        encClID.encryptedClientIDIv = Data(encIv)
        //PKCS1_OAEP.new(RSA.importKey(serviceCert.publicKey).encrypt(encKey)
        do {
            let rsaPublicKey = try RSAPublicKey(der: [UInt8].init(serviceCert.publicKey), format: .X509)
            let encPrivacyKey = try rsaPublicKey.encryptOAEP(message: encKey, kind: .SHA1)
            encClID.encryptedPrivacyKey = Data(encPrivacyKey)
        } catch {
            #if DEBUG
            print(error)
            #endif
            return .failure(.cryptographyFail(description: "Unable to encrypt AES encryption key; " + error.localizedDescription))
        }
        return .success(encClID)
    }
    
    ///Returns 3 keys derived from the input message
    ///Key can either be a pre-provision device aes key, provision key, or a session key.
    ///
    ///For provisioning:
    ///- enc: aes key used for unwrapping RSA key out of response
    ///- mac_key_server: hmac-sha256 key used for verifying provisioning response
    ///- mac_key_client: hmac-sha256 key used for signing provisioning request
    ///
    ///When used with a session key:
    ///- enc: decrypting content and other keys
    ///- mac_key_server: verifying response
    ///- mac_key_client: renewals
    ///
    ///With key as pre-provision device key, it can be used to provision and get an RSA device key and token/cert with key as session key (OAEP wrapped with the post-provision RSA device key), it can be used to decrypt content and signing keys and verify licenses.
    static func deriveKeys(encContext: [UInt8], macContext: [UInt8], key: [UInt8]) -> Result<([UInt8], [UInt8], [UInt8]), WDVError> {
        /*let cmacEng: CMAC
        do {
            cmacEng = try CMAC(key: key)
        } catch {
            #if DEBUG
            print(error)
            #endif
            return .failure(.cryptographyFail(description: "Init CMAC (AES) fail; " + error.localizedDescription))
        }*/
        //CMAC.new(session_key, ciphermod=AES)
        //_derive => CMAC.new(session_key, ciphermod=AES).update(counter.to_bytes(1, "big") + context).digest()
        //_derive(key, enc_context, 1)
        var buff: [UInt8] = [UInt8].init(encContext)
        buff.insert(1, at: 0)
        let encKey: [UInt8] = WDVCryptoUtil.aesCmac(msg: buff, key: key)
        /*do {
            encKey = try cmacEng.authenticate(buff)
        } catch {
#if DEBUG
            print(error)
#endif
            return .failure(.cryptographyFail(description: "Encryption key authenticate fail; " + error.localizedDescription))
        }*/
        //_derive(key, mac_context, 1)
        buff = [UInt8].init(macContext)
        buff.insert(1, at: 0)
        var macKeySrv: [UInt8] = WDVCryptoUtil.aesCmac(msg: buff, key: key)
        /*do {
            macKeySrv = try cmacEng.authenticate(buff)
        } catch {
#if DEBUG
            print(error)
#endif
            return .failure(.cryptographyFail(description: "Server key authenticate fail; " + error.localizedDescription))
        }*/
        //_derive(key, mac_context, 2)
        buff[0] = 2
        macKeySrv.append(contentsOf: WDVCryptoUtil.aesCmac(msg: buff, key: key))
        /*do {
            macKeySrv.append(contentsOf: try cmacEng.authenticate(buff))
        } catch {
#if DEBUG
            print(error)
#endif
            return .failure(.cryptographyFail(description: "Server key authenticate fail; " + error.localizedDescription))
        }*/
        //_derive(key, mac_context, 3)
        buff[0] = 3
        var macKeyClient: [UInt8] = WDVCryptoUtil.aesCmac(msg: buff, key: key)
        /*do {
            macKeyClient = try cmacEng.authenticate(buff)
        } catch {
#if DEBUG
            print(error)
#endif
            return .failure(.cryptographyFail(description: "Client key authenticate fail; " + error.localizedDescription))
        }*/
        //_derive(key, mac_context, 4)
        buff[0] = 4
        macKeyClient.append(contentsOf: WDVCryptoUtil.aesCmac(msg: buff, key: key))
        /*do {
            macKeyClient.append(contentsOf: try cmacEng.authenticate(buff))
        } catch {
#if DEBUG
            print(error)
#endif
            return .failure(.cryptographyFail(description: "Client key authenticate fail; " + error.localizedDescription))
        }*/
        return .success((encKey,macKeySrv,macKeyClient))
    }
}
