//
//  BinaryIntExt.swift
//  SwWidevine
//
//  Created by developer on 18.07.2024.
//

///Bytes view representation for binary integer values
protocol WDVBinaryIntegerByteView {
    ///Big-Endian bytes view
    var beBytes: [UInt8] {
         get
    }
    
    ///Little-Endian bytes view
    var leBytes: [UInt8] {
        get
    }
}

extension UInt64: WDVBinaryIntegerByteView {
    var beBytes: [UInt8] {
        get {
            return leBytes.reversed()
        }
    }
    
    var leBytes: [UInt8] {
        get {
            return WDVBinaryUtil.getLEndianBytes(self)
        }
    }
}

extension UInt32: WDVBinaryIntegerByteView {
    var beBytes: [UInt8] {
        get {
            return leBytes.reversed()
        }
    }
    
    var leBytes: [UInt8] {
        get {
            return WDVBinaryUtil.getLEndianBytes(self)
        }
    }
}

extension UInt16: WDVBinaryIntegerByteView {
    var beBytes: [UInt8] {
        get {
            return leBytes.reversed()
        }
    }
    
    var leBytes: [UInt8] {
        get {
            return WDVBinaryUtil.getLEndianBytes(self)
        }
    }
}

extension UInt8: WDVBinaryIntegerByteView {
    var beBytes: [UInt8] {
        get {
            return [self]
        }
    }
    
    var leBytes: [UInt8] {
        get {
            return beBytes
        }
    }
}

extension Int8: WDVBinaryIntegerByteView {
    var beBytes: [UInt8] {
        get {
            let uVal = UInt8(bitPattern: self)
            return [uVal]
        }
    }
    
    var leBytes: [UInt8] {
        get {
            return beBytes
        }
    }
}

extension Int16: WDVBinaryIntegerByteView {
    var beBytes: [UInt8] {
        get {
            return leBytes.reversed()
        }
    }
    
    var leBytes: [UInt8] {
        get {
            let uVal = UInt16(bitPattern: self)
            return uVal.leBytes
        }
    }
}

extension Int32: WDVBinaryIntegerByteView {
    var beBytes: [UInt8] {
        get {
            return leBytes.reversed()
        }
    }
    
    var leBytes: [UInt8] {
        get {
            let uVal = UInt32(bitPattern: self)
            return uVal.leBytes
        }
    }
}

extension Int64: WDVBinaryIntegerByteView {
    var beBytes: [UInt8] {
        get {
            return leBytes.reversed()
        }
    }
    
    var leBytes: [UInt8] {
        get {
            let uVal = UInt64(bitPattern: self)
            return uVal.leBytes
        }
    }
}
