//
//  OpenPGPPrivateKey.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-23.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension BCOpenpgpPGPPrivateKey {

    /// hex BCOpenPGP KeyID  
    public var keyID: String {
        return String(fromPGPKeyID: getID())
    }

}
