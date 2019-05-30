//
//  StringHelper.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-29.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension String {

    /// Convert BCOpenPGP key ID to Hex format key ID
    ///
    /// - Parameter keyID: jlong type key ID
    public init(fromPGPKeyID keyID: jlong) {
        let data = withUnsafeBytes(of: keyID) { Data($0) }
        let string = data.toHexString().uppercased()
        assert(string.count == 16)
        self.init(string)
        assert(toPGPKeyID == keyID)
    }


    /// Restore Hex format key id to jlong (Int64) format key id
    /// Note: - Use positive & negative of return value to interact with BCOpenPGP API
    public var toPGPKeyID: jlong? {
        assert(self.count == 16)
        guard let data = self.hexadecimal, data.count == 8 else {
            assertionFailure()
            return nil
        }

        do {
            let keyID: Int64 = data.withUnsafeBytes { $0.pointee }
            return keyID
        } catch {
            assertionFailure()

            return nil
        }
    }

    var hexadecimal: Data? {
        var hex = self
        var data = Data()
        while(hex.count > 0) {
            let subIndex = hex.index(hex.startIndex, offsetBy: 2)
            let c = String(hex[..<subIndex])
            hex = String(hex[subIndex...])
            var ch: UInt32 = 0
            Scanner(string: c).scanHexInt32(&ch)
            var char = UInt8(ch)
            data.append(&char, count: 1)
        }
        return data
    }

}
