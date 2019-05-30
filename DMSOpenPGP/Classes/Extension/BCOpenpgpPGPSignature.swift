//
//  BCOpenpgpPGPSignature.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-30.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension BCOpenpgpPGPSignature {

    public var keyID: String {
        return String(fromPGPKeyID: getKeyID())
    }

}
