//
//  WDVCMAC.swift
//  SwWidevine
//
//  Created by developer on 23.08.2024.
//

final class WDVCMAC {
  enum Error: Swift.Error {
    case wrongKeyLength
  }

  internal let key: Array<UInt8>

  internal static let BlockSize: Int = 16
  internal static let Zero: Array<UInt8> = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
  private static let Rb: Array<UInt8> = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87]

  init(key: Array<UInt8>) {
    self.key = key
  }

    // AES-CMAC
  func authenticate(_ bytes: Array<UInt8>) -> Array<UInt8> {
    let l = WDVCryptoUtil.aesCbcNoPaddingEncrypt(msg: WDVCMAC.Zero, key: key, iv: WDVCMAC.Zero)
    var subKey1 = self.leftShiftOneBit(l)
    if (l[0] & 0x80) != 0 {
      subKey1 = xor(WDVCMAC.Rb, subKey1)
    }
    var subKey2 = self.leftShiftOneBit(subKey1)
    if (subKey1[0] & 0x80) != 0 {
      subKey2 = xor(WDVCMAC.Rb, subKey2)
    }

    let lastBlockComplete: Bool
    let blockCount = (bytes.count + WDVCMAC.BlockSize - 1) / WDVCMAC.BlockSize
    if blockCount == 0 {
      lastBlockComplete = false
    } else {
      lastBlockComplete = bytes.count % WDVCMAC.BlockSize == 0
    }
    var paddedBytes = bytes
    if !lastBlockComplete {
      bitPadding(to: &paddedBytes, blockSize: WDVCMAC.BlockSize)
    }

    var blocks = Array(paddedBytes.batched(by: WDVCMAC.BlockSize))
    var lastBlock = blocks.popLast()!
    if lastBlockComplete {
      lastBlock = xor(lastBlock, subKey1)
    } else {
      lastBlock = xor(lastBlock, subKey2)
    }

    var x = Array<UInt8>(repeating: 0x00, count: WDVCMAC.BlockSize)
    var y = Array<UInt8>(repeating: 0x00, count: WDVCMAC.BlockSize)
    for block in blocks {
      y = xor(block, x)
        x = WDVCryptoUtil.aesCbcNoPaddingEncrypt(msg: y, key: key, iv: WDVCMAC.Zero)
    }
    // the difference between CMAC and CBC-MAC is that CMAC xors the final block with a secret value
    y = self.process(lastBlock: lastBlock, with: x)
    return WDVCryptoUtil.aesCbcNoPaddingEncrypt(msg: y, key: key, iv: WDVCMAC.Zero)
  }

  func process(lastBlock: ArraySlice<UInt8>, with x: [UInt8]) -> [UInt8] {
    xor(lastBlock, x)
  }

  // MARK: Helper methods

  /**
   Performs left shift by one bit to the bit string aquired after concatenating al bytes in the byte array
   - parameters:
   - bytes: byte array
   - returns: bit shifted bit string split again in array of bytes
   */
  private func leftShiftOneBit(_ bytes: Array<UInt8>) -> Array<UInt8> {
    var shifted = Array<UInt8>(repeating: 0x00, count: bytes.count)
    let last = bytes.count - 1
    for index in 0..<last {
      shifted[index] = bytes[index] << 1
      if (bytes[index + 1] & 0x80) != 0 {
        shifted[index] += 0x01
      }
    }
    shifted[last] = bytes[last] << 1
    return shifted
  }
    
    private func xor<T, V>(_ left: T, _ right: V) -> ArraySlice<UInt8> where T: RandomAccessCollection, V: RandomAccessCollection, T.Element == UInt8, T.Index == Int, V.Element == UInt8, V.Index == Int {
        let res: Array<UInt8> = xor(left, right)
        return ArraySlice(res)
    }

    private func xor<T, V>(_ left: T, _ right: V) -> Array<UInt8> where T: RandomAccessCollection, V: RandomAccessCollection, T.Element == UInt8, T.Index == Int, V.Element == UInt8, V.Index == Int {
      let length = Swift.min(left.count, right.count)

      let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: length)
      buf.initialize(repeating: 0, count: length)
      defer {
        buf.deinitialize(count: length)
        buf.deallocate()
      }

      // xor
      for i in 0..<length {
        buf[i] = left[left.startIndex.advanced(by: i)] ^ right[right.startIndex.advanced(by: i)]
      }

      return Array(UnsafeBufferPointer(start: buf, count: length))
    }
    
    /**
     ISO/IEC 9797-1 Padding method 2.
     Add a single bit with value 1 to the end of the data.
     If necessary add bits with value 0 to the end of the data until the padded data is a multiple of blockSize.
     - parameters:
     - blockSize: Padding size in bytes.
     - allowance: Excluded trailing number of bytes.
     */
    private func bitPadding(to data: inout Array<UInt8>, blockSize: Int, allowance: Int = 0) {
      let msgLength = data.count
      // Step 1. Append Padding Bits
      // append one bit (UInt8 with one bit) to message
      data.append(0x80)

      // Step 2. append "0" bit until message length in bits ≡ 448 (mod 512)
      let max = blockSize - allowance // 448, 986
      if msgLength % blockSize < max { // 448
        data += Array<UInt8>(repeating: 0, count: max - 1 - (msgLength % blockSize))
      } else {
        data += Array<UInt8>(repeating: 0, count: blockSize + max - 1 - (msgLength % blockSize))
      }
    }
}

@usableFromInline
struct BatchedCollectionIndex<Base: Collection> {
  let range: Range<Base.Index>
}

extension BatchedCollectionIndex: Comparable {
  @usableFromInline
  static func == <BaseCollection>(lhs: BatchedCollectionIndex<BaseCollection>, rhs: BatchedCollectionIndex<BaseCollection>) -> Bool {
    lhs.range.lowerBound == rhs.range.lowerBound
  }

  @usableFromInline
  static func < <BaseCollection>(lhs: BatchedCollectionIndex<BaseCollection>, rhs: BatchedCollectionIndex<BaseCollection>) -> Bool {
    lhs.range.lowerBound < rhs.range.lowerBound
  }
}

struct BatchedCollection<Base: Collection>: Collection {
  let base: Base
  let size: Int

  @usableFromInline
  init(base: Base, size: Int) {
    self.base = base
    self.size = size
  }

  @usableFromInline
  typealias Index = BatchedCollectionIndex<Base>

  private func nextBreak(after idx: Base.Index) -> Base.Index {
    self.base.index(idx, offsetBy: self.size, limitedBy: self.base.endIndex) ?? self.base.endIndex
  }

  @usableFromInline
  var startIndex: Index {
    Index(range: self.base.startIndex..<self.nextBreak(after: self.base.startIndex))
  }

  @usableFromInline
  var endIndex: Index {
    Index(range: self.base.endIndex..<self.base.endIndex)
  }

  @usableFromInline
  func index(after idx: Index) -> Index {
    Index(range: idx.range.upperBound..<self.nextBreak(after: idx.range.upperBound))
  }

  @usableFromInline
  subscript(idx: Index) -> Base.SubSequence {
    self.base[idx.range]
  }
}

extension Collection {
  func batched(by size: Int) -> BatchedCollection<Self> {
    BatchedCollection(base: self, size: size)
  }
}
