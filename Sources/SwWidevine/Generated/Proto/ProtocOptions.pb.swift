// DO NOT EDIT.
// swift-format-ignore-file
//
// Generated by the Swift generator plugin for the protocol buffer compiler.
// Source: ProtocOptions.proto
//
// For information on using the generated types, please see the documentation:
//   https://github.com/apple/swift-protobuf/

import Foundation
import SwiftProtobuf

// If the compiler emits an error on this type, it is because this file
// was generated by a version of the `protoc` Swift plug-in that is
// incompatible with the version of SwiftProtobuf to which you are linking.
// Please ensure that you are building against the same version of the API
// that was used to generate this file.
fileprivate struct _GeneratedWithProtocGenSwiftVersion: SwiftProtobuf.ProtobufAPIVersionCheck {
  struct _2: SwiftProtobuf.ProtobufAPIVersion_2 {}
  typealias Version = _2
}

enum Google_Protobuf_AccessControl: SwiftProtobuf.Enum {
  typealias RawValue = Int
  case internalEntities // = 0
  case publicEntities // = 1
  case UNRECOGNIZED(Int)

  init() {
    self = .internalEntities
  }

  init?(rawValue: Int) {
    switch rawValue {
    case 0: self = .internalEntities
    case 1: self = .publicEntities
    default: self = .UNRECOGNIZED(rawValue)
    }
  }

  var rawValue: Int {
    switch self {
    case .internalEntities: return 0
    case .publicEntities: return 1
    case .UNRECOGNIZED(let i): return i
    }
  }

}

#if swift(>=4.2)

extension Google_Protobuf_AccessControl: CaseIterable {
  // The compiler won't synthesize support with the UNRECOGNIZED case.
  static let allCases: [Google_Protobuf_AccessControl] = [
    .internalEntities,
    .publicEntities,
  ]
}

#endif  // swift(>=4.2)

struct Google_Protobuf_SwiftFileOptions {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var classPrefix: String {
    get {return _classPrefix ?? String()}
    set {_classPrefix = newValue}
  }
  /// Returns true if `classPrefix` has been explicitly set.
  var hasClassPrefix: Bool {return self._classPrefix != nil}
  /// Clears the value of `classPrefix`. Subsequent reads from it will return its default value.
  mutating func clearClassPrefix() {self._classPrefix = nil}

  var entitiesAccessControl: Google_Protobuf_AccessControl {
    get {return _entitiesAccessControl ?? .internalEntities}
    set {_entitiesAccessControl = newValue}
  }
  /// Returns true if `entitiesAccessControl` has been explicitly set.
  var hasEntitiesAccessControl: Bool {return self._entitiesAccessControl != nil}
  /// Clears the value of `entitiesAccessControl`. Subsequent reads from it will return its default value.
  mutating func clearEntitiesAccessControl() {self._entitiesAccessControl = nil}

  var compileForFramework: Bool {
    get {return _compileForFramework ?? false}
    set {_compileForFramework = newValue}
  }
  /// Returns true if `compileForFramework` has been explicitly set.
  var hasCompileForFramework: Bool {return self._compileForFramework != nil}
  /// Clears the value of `compileForFramework`. Subsequent reads from it will return its default value.
  mutating func clearCompileForFramework() {self._compileForFramework = nil}

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}

  fileprivate var _classPrefix: String? = nil
  fileprivate var _entitiesAccessControl: Google_Protobuf_AccessControl? = nil
  fileprivate var _compileForFramework: Bool? = nil
}

struct Google_Protobuf_SwiftMessageOptions {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var generateErrorType: Bool {
    get {return _generateErrorType ?? false}
    set {_generateErrorType = newValue}
  }
  /// Returns true if `generateErrorType` has been explicitly set.
  var hasGenerateErrorType: Bool {return self._generateErrorType != nil}
  /// Clears the value of `generateErrorType`. Subsequent reads from it will return its default value.
  mutating func clearGenerateErrorType() {self._generateErrorType = nil}

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}

  fileprivate var _generateErrorType: Bool? = nil
}

struct Google_Protobuf_SwiftEnumOptions {
  // SwiftProtobuf.Message conformance is added in an extension below. See the
  // `Message` and `Message+*Additions` files in the SwiftProtobuf library for
  // methods supported on all messages.

  var generateErrorType: Bool {
    get {return _generateErrorType ?? false}
    set {_generateErrorType = newValue}
  }
  /// Returns true if `generateErrorType` has been explicitly set.
  var hasGenerateErrorType: Bool {return self._generateErrorType != nil}
  /// Clears the value of `generateErrorType`. Subsequent reads from it will return its default value.
  mutating func clearGenerateErrorType() {self._generateErrorType = nil}

  var unknownFields = SwiftProtobuf.UnknownStorage()

  init() {}

  fileprivate var _generateErrorType: Bool? = nil
}

#if swift(>=5.5) && canImport(_Concurrency)
extension Google_Protobuf_AccessControl: @unchecked Sendable {}
extension Google_Protobuf_SwiftFileOptions: @unchecked Sendable {}
extension Google_Protobuf_SwiftMessageOptions: @unchecked Sendable {}
extension Google_Protobuf_SwiftEnumOptions: @unchecked Sendable {}
#endif  // swift(>=5.5) && canImport(_Concurrency)

// MARK: - Extension support defined in ProtocOptions.proto.

// MARK: - Extension Properties

// Swift Extensions on the exteneded Messages to add easy access to the declared
// extension fields. The names are based on the extension field name from the proto
// declaration. To avoid naming collisions, the names are prefixed with the name of
// the scope where the extend directive occurs.

extension SwiftProtobuf.Google_Protobuf_EnumOptions {

  var Google_Protobuf_swiftEnumOptions: Google_Protobuf_SwiftEnumOptions {
    get {return getExtensionValue(ext: Google_Protobuf_Extensions_swift_enum_options) ?? Google_Protobuf_SwiftEnumOptions()}
    set {setExtensionValue(ext: Google_Protobuf_Extensions_swift_enum_options, value: newValue)}
  }
  /// Returns true if extension `Google_Protobuf_Extensions_swift_enum_options`
  /// has been explicitly set.
  var hasGoogle_Protobuf_swiftEnumOptions: Bool {
    return hasExtensionValue(ext: Google_Protobuf_Extensions_swift_enum_options)
  }
  /// Clears the value of extension `Google_Protobuf_Extensions_swift_enum_options`.
  /// Subsequent reads from it will return its default value.
  mutating func clearGoogle_Protobuf_swiftEnumOptions() {
    clearExtensionValue(ext: Google_Protobuf_Extensions_swift_enum_options)
  }
}

extension SwiftProtobuf.Google_Protobuf_FileOptions {

  var Google_Protobuf_swiftFileOptions: Google_Protobuf_SwiftFileOptions {
    get {return getExtensionValue(ext: Google_Protobuf_Extensions_swift_file_options) ?? Google_Protobuf_SwiftFileOptions()}
    set {setExtensionValue(ext: Google_Protobuf_Extensions_swift_file_options, value: newValue)}
  }
  /// Returns true if extension `Google_Protobuf_Extensions_swift_file_options`
  /// has been explicitly set.
  var hasGoogle_Protobuf_swiftFileOptions: Bool {
    return hasExtensionValue(ext: Google_Protobuf_Extensions_swift_file_options)
  }
  /// Clears the value of extension `Google_Protobuf_Extensions_swift_file_options`.
  /// Subsequent reads from it will return its default value.
  mutating func clearGoogle_Protobuf_swiftFileOptions() {
    clearExtensionValue(ext: Google_Protobuf_Extensions_swift_file_options)
  }
}

extension SwiftProtobuf.Google_Protobuf_MessageOptions {

  var Google_Protobuf_swiftMessageOptions: Google_Protobuf_SwiftMessageOptions {
    get {return getExtensionValue(ext: Google_Protobuf_Extensions_swift_message_options) ?? Google_Protobuf_SwiftMessageOptions()}
    set {setExtensionValue(ext: Google_Protobuf_Extensions_swift_message_options, value: newValue)}
  }
  /// Returns true if extension `Google_Protobuf_Extensions_swift_message_options`
  /// has been explicitly set.
  var hasGoogle_Protobuf_swiftMessageOptions: Bool {
    return hasExtensionValue(ext: Google_Protobuf_Extensions_swift_message_options)
  }
  /// Clears the value of extension `Google_Protobuf_Extensions_swift_message_options`.
  /// Subsequent reads from it will return its default value.
  mutating func clearGoogle_Protobuf_swiftMessageOptions() {
    clearExtensionValue(ext: Google_Protobuf_Extensions_swift_message_options)
  }

}

// MARK: - File's ExtensionMap: Google_Protobuf_ProtocOptions_Extensions

/// A `SwiftProtobuf.SimpleExtensionMap` that includes all of the extensions defined by
/// this .proto file. It can be used any place an `SwiftProtobuf.ExtensionMap` is needed
/// in parsing, or it can be combined with other `SwiftProtobuf.SimpleExtensionMap`s to create
/// a larger `SwiftProtobuf.SimpleExtensionMap`.
let Google_Protobuf_ProtocOptions_Extensions: SwiftProtobuf.SimpleExtensionMap = [
  Google_Protobuf_Extensions_swift_file_options,
  Google_Protobuf_Extensions_swift_message_options,
  Google_Protobuf_Extensions_swift_enum_options
]

// Extension Objects - The only reason these might be needed is when manually
// constructing a `SimpleExtensionMap`, otherwise, use the above _Extension Properties_
// accessors for the extension fields on the messages directly.

let Google_Protobuf_Extensions_swift_file_options = SwiftProtobuf.MessageExtension<SwiftProtobuf.OptionalMessageExtensionField<Google_Protobuf_SwiftFileOptions>, SwiftProtobuf.Google_Protobuf_FileOptions>(
  _protobuf_fieldNumber: 5092014,
  fieldName: "google.protobuf.swift_file_options"
)

let Google_Protobuf_Extensions_swift_message_options = SwiftProtobuf.MessageExtension<SwiftProtobuf.OptionalMessageExtensionField<Google_Protobuf_SwiftMessageOptions>, SwiftProtobuf.Google_Protobuf_MessageOptions>(
  _protobuf_fieldNumber: 5092014,
  fieldName: "google.protobuf.swift_message_options"
)

let Google_Protobuf_Extensions_swift_enum_options = SwiftProtobuf.MessageExtension<SwiftProtobuf.OptionalMessageExtensionField<Google_Protobuf_SwiftEnumOptions>, SwiftProtobuf.Google_Protobuf_EnumOptions>(
  _protobuf_fieldNumber: 5092015,
  fieldName: "google.protobuf.swift_enum_options"
)

// MARK: - Code below here is support for the SwiftProtobuf runtime.

fileprivate let _protobuf_package = "google.protobuf"

extension Google_Protobuf_AccessControl: SwiftProtobuf._ProtoNameProviding {
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    0: .same(proto: "InternalEntities"),
    1: .same(proto: "PublicEntities"),
  ]
}

extension Google_Protobuf_SwiftFileOptions: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".SwiftFileOptions"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "class_prefix"),
    2: .standard(proto: "entities_access_control"),
    3: .standard(proto: "compile_for_framework"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularStringField(value: &self._classPrefix) }()
      case 2: try { try decoder.decodeSingularEnumField(value: &self._entitiesAccessControl) }()
      case 3: try { try decoder.decodeSingularBoolField(value: &self._compileForFramework) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if let v = self._classPrefix {
      try visitor.visitSingularStringField(value: v, fieldNumber: 1)
    } }()
    try { if let v = self._entitiesAccessControl {
      try visitor.visitSingularEnumField(value: v, fieldNumber: 2)
    } }()
    try { if let v = self._compileForFramework {
      try visitor.visitSingularBoolField(value: v, fieldNumber: 3)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Google_Protobuf_SwiftFileOptions, rhs: Google_Protobuf_SwiftFileOptions) -> Bool {
    if lhs._classPrefix != rhs._classPrefix {return false}
    if lhs._entitiesAccessControl != rhs._entitiesAccessControl {return false}
    if lhs._compileForFramework != rhs._compileForFramework {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Google_Protobuf_SwiftMessageOptions: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".SwiftMessageOptions"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "generate_error_type"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBoolField(value: &self._generateErrorType) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if let v = self._generateErrorType {
      try visitor.visitSingularBoolField(value: v, fieldNumber: 1)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Google_Protobuf_SwiftMessageOptions, rhs: Google_Protobuf_SwiftMessageOptions) -> Bool {
    if lhs._generateErrorType != rhs._generateErrorType {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}

extension Google_Protobuf_SwiftEnumOptions: SwiftProtobuf.Message, SwiftProtobuf._MessageImplementationBase, SwiftProtobuf._ProtoNameProviding {
  static let protoMessageName: String = _protobuf_package + ".SwiftEnumOptions"
  static let _protobuf_nameMap: SwiftProtobuf._NameMap = [
    1: .standard(proto: "generate_error_type"),
  ]

  mutating func decodeMessage<D: SwiftProtobuf.Decoder>(decoder: inout D) throws {
    while let fieldNumber = try decoder.nextFieldNumber() {
      // The use of inline closures is to circumvent an issue where the compiler
      // allocates stack space for every case branch when no optimizations are
      // enabled. https://github.com/apple/swift-protobuf/issues/1034
      switch fieldNumber {
      case 1: try { try decoder.decodeSingularBoolField(value: &self._generateErrorType) }()
      default: break
      }
    }
  }

  func traverse<V: SwiftProtobuf.Visitor>(visitor: inout V) throws {
    // The use of inline closures is to circumvent an issue where the compiler
    // allocates stack space for every if/case branch local when no optimizations
    // are enabled. https://github.com/apple/swift-protobuf/issues/1034 and
    // https://github.com/apple/swift-protobuf/issues/1182
    try { if let v = self._generateErrorType {
      try visitor.visitSingularBoolField(value: v, fieldNumber: 1)
    } }()
    try unknownFields.traverse(visitor: &visitor)
  }

  static func ==(lhs: Google_Protobuf_SwiftEnumOptions, rhs: Google_Protobuf_SwiftEnumOptions) -> Bool {
    if lhs._generateErrorType != rhs._generateErrorType {return false}
    if lhs.unknownFields != rhs.unknownFields {return false}
    return true
  }
}