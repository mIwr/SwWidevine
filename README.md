# SwWidevine - Swift Widevine CDM implementation

[![Swift Package Manager compatible](https://img.shields.io/badge/SPM-compatible-brightgreen.svg?style=flat&colorA=28a745&&colorB=4E4E4E)](https://github.com/apple/swift-package-manager)
[![Platform](https://img.shields.io/badge/Platforms-iOS%20%7C%20Android%20%7CmacOS%20%7C%20watchOS%20%7C%20tvOS%20%7C%20Linux-4E4E4E.svg?colorA=28a745)](#Setup)


<p align="center">
    <a href="https://github.com/apple/swift">
        <img src="https://img.shields.io/badge/language-swift-orange.svg">
    </a>
    <a href="http://cocoapods.org/pods/SwWidevine">
        <img src="https://img.shields.io/cocoapods/v/SwWidevine.svg?style=flat">
    </a>
    <a href="http://cocoapods.org/pods/SwWidevine">
        <img src="https://img.shields.io/cocoapods/p/SwWidevine.svg?style=flat">
    </a>
    <a href="./LICENSE">
        <img src="https://img.shields.io/cocoapods/l/SwWidevine.svg?style=flat">
    </a>
</p>

## Content

- [Disclaimer](#Disclaimer)

- [Introduction](#Introduction)

- [Features](#Features)

- [Setup](#Setup)

- [Getting started](#Getting-started)

- [DRM license acquire](#DRM-license-acquire)

## Disclaimer

1. This project requires a valid Google-provisioned Private Key and Client Identification blob which are not
   provided by this project.
2. Public test provisions are available and provided by Google to use for testing projects such as this one.
3. License Servers have the ability to block requests from any provision, and are likely already blocking test
   provisions on production endpoints.
4. This project does not condone piracy or any action against the terms of the DRM systems.
5. All efforts in this project have been the result of Reverse-Engineering, Publicly available research, and Trial
   & Error.

## Introduction

The library allows to do License Acquisition within the CDM

macOS 10.13+, iOS 11.0+ and Windows are supported by the module code base. Other platforms (tvOS 11.0+, watchOS 4.0+ for CocoaPods and 5.0+ for SPM, visionOS 1.0+, Linux, Android) have experimental support

**Notice: XCode 15+ doesn't allow to use iOS 11, tvOS 11 as minimum deployment target during build process. So the mimimum deployment target for these platforms in your project must be 12 in fact.**
**If you want to bypass this limitation, you have to roll back to XCode 14.** More info: [1](https://github.com/Alamofire/Alamofire/pull/3823), [2](https://github.com/realm/realm-swift/issues/8368#issuecomment-1737604011)

## Features

- Pure swift CDM implementation
- Widevine L3 supported
- Generating the DRM License Challenge request
- DRM service certificates support (For encrypting client info)
- Processing DRM server License response with extracting content keys

**Notice: the module doesn't provide pack/unpack tools for DRM content**

## Setup

### Swift Package Manager

SwWidevine is available with SPM

```
.package(url: "https://github.com/mIwr/SwWidevine.git", .from(from: "1.1.2"))
```

### CocoaPods

SwWidevine is available with CocoaPods. To install a module, just add to the Podfile:

- iOS
```ruby
platform :ios, '11.0'
...
pod 'SwPSSH'
pod 'SwWidevine'
```

- macOS
```ruby
platform :osx, '10.13'
...
pod 'SwPSSH'
pod 'SwWidevine'
```

- tvOS
```ruby
platform :tvos, '11.0'
...
pod 'SwPSSH'
pod 'SwWidevine'
```

- watchOS
```ruby
platform :watchos, '4.0'
...
pod 'SwPSSH'
pod 'SwWidevine'
```

## Getting started

CDM main logic is contained at [WDVCDMController](./Sources/SwWidevine/WDVCDMController.swift) class.

1. To init CDM controller you need [WDVDevice](./Sources/SwWidevine/Model/Device/WDVDevice.swift) instance, which contains RSA private key and client info
```swift
import SwWidevine
//...
let wdvData: [UInt8]
//...Acquiring device data...
guard let device: WDVDevice = WDVDevice.from(wdvBytes: wdvBytes) else {return}
let wdvCdm: WDVCDMController
do {
  wdvCdm = try WDVCDMController(device: device)
} catch {
  return
}
```

2. Get provider application 'privacy' certificate if exists and required (protobuf SignedDrmCertificate) 

3. Now you can create the session for working with CDM
```swift
let serviceCert: WDVSignedDrmCertificate?
//...Acquiring application 'privacy' certificate...
let creationRes: Result<WDVSession, WDVError> = wdvCdm.openNewSession(serviceCertificate: serviceCert)
let session: WDVSession
do {
  session = try creationRes.get()
} catch {
  return
}
```

**Notice: Session maximum count is programmaticaly limited to 16 at the moment for single controller**

## DRM license acquire

### Generating DRM License Challenge request

To make the License Challenge request you need to provide:

- CDM session
- DRM content PSSH

```swift
import SwPSSH
import SwWidevine
//...
let cdmController: WDVCDMController
let appCrt: WDVSignedDrmCertificate?
let pssh: PSSHBox
//...init controller, service privacy certificate and PSSH box container...
let openRes = cdmController.openNewSession(serviceCertificate: appCrt)
guard let safeSession = try? openRes.get() else {return}
let licReqRes = cdmController.generateLicChallenge(sessionHexId: safeSession.hexId, pssh: pssh, licenseType: .streaming, privacyMode: true)
guard let safeLicReq: [UInt8] = try? licReqRes.get() else {return}
```

CDM controller will return raw protobuf bytes of the generated and signed request message. Message has to be sent to DRM license server according provided API
 
**Each created License Challenge request will be cached on the session context for further DRM server license response processing**
 
### Processing DRM server license response

Received from DRM server the license response is a protobuf SignedMessage instance. 
```swift
let licSrvResponseData: Data
//...Generate license request and send to license server...
let parseRes = cdmController.extractKeyFromLicenseMsg(sessionHexId: safeSession.hexId, licSrvResponse: data)
guard let safeKeys: [WDVContentKey] = try? parseRes.get() else {return}
```
Controller will extract content key from response. Also it will cache the key on session key storage.

Further step is providing key ID and key data for unpacker (mp4decrypt, shaka-packager or ffmpeg, for example)

**shaka-packager unpack cmd example**
```
./packager in=input_file,stream=0,output=output_file --enable_raw_key_decryption --keys label=1:key_id={Key ID hex string}:key={Key data hex string}
```

**ffmpeg unpack cmd example**
```
./ffmpeg -decryption_key {Key data hex string} -i input_file output_file
```
