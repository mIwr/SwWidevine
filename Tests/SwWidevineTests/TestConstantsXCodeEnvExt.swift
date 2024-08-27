//
//  TestConstansXCodeEnvExt.swift
//  SwWidevine
//
//  Created by developer on 09.08.2024.
//

import Foundation

extension TestConstants {
    
    static var testBundle: Bundle {
        get {
            return Bundle(for: Self.self)
        }
    }
}
