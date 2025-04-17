Pod::Spec.new do |spec|
  spec.name         = "SwWidevine"
  spec.version      = "1.1.2"
  spec.summary      = "Swift Widevine CDM implementation"
  spec.homepage     = "https://github.com/mIwr/SwWidevine"
  spec.license      = { :type => "MIT", :file => "LICENSE" }
  spec.author       = { "mIwr" => "https://github.com/mIwr" }
  spec.osx.deployment_target = "10.13"
  spec.ios.deployment_target = "11.0"
  spec.tvos.deployment_target = "11.0"
  spec.watchos.deployment_target = "4.0"
  spec.swift_version = "5.0"
  spec.source        = { :git => "https://github.com/mIwr/SwWidevine.git", :tag => "#{spec.version}" }
  spec.source_files  = "Sources/SwWidevine/*.swift", "Sources/SwWidevine/**/*.swift"
  spec.exclude_files = "Sources/Exclude", "Sources/Exclude/*.*"
  spec.framework     = "Foundation"
  spec.dependency    "SwiftProtobuf"
  spec.dependency    "SwiftRSA"
  spec.dependency    "SwPSSH"
  spec.resource_bundles = {'SwWidevine' => ['Sources/SwWidevine/PrivacyInfo.xcprivacy']}
end
