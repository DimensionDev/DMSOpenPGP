//
//  OpenPGPKeyRing.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-24.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension BCOpenpgpPGPKeyRing {

    public func armored() -> String {
        let output = JavaIoByteArrayOutputStream()
        let armoredOutput = TCKeyArmoredOutputStream(javaIoOutputStream: output)
        encode(with: armoredOutput)
        armoredOutput.close()
        output.close()

        return output.toString(with: "UTF-8")
    }

    public func export() -> Data {
        let output = JavaIoByteArrayOutputStream()
        encode(with: output)
        output.close()

        guard let data = output.toByteArray()?.toNSData() else {
            fatalError()
        }

        return data
    }

}
