//
//  DMSPGPError.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-19.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public enum DMSPGPError: Error {
    case `internal`

    case notArmoredInput
    case invalidArmored

    case invalidKeyID
    case invalidCleartext
    case invalidMessage
    case invalidPublicKeyRing
    case invalidSecretKeyRing
    case invalidPrivateKey
    case invalidSecrectKeyPassword
    case invalidCurve
    case invalidKeyLength
    case notSupportAlgorithm(DMSPGPPublicKeyAlgorithm)

    case missingEncryptionKey(keyRings: [BCOpenpgpPGPPublicKeyRing])
}


