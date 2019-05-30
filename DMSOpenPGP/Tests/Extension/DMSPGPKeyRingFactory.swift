//
//  DMSPGPKeyRingFactory.swift
//  TesserCubeTests
//
//  Created by Cirno MainasuK on 2019-5-20.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import DMSOpenPGP

extension DMSPGPKeyRingFactory {

    convenience init(userID: String, password: String, onEC: Bool = false) throws {
        let meta = DMSPGPUserIDTranslator(userID: userID)
        var masterkeyData = KeyData()
        var subkeyData = KeyData()
        if onEC {
            masterkeyData.algorithm = .ECDSA
            masterkeyData.curve = .Secp256k1

            subkeyData.algorithm = .ELGAMAL_ENCRYPT
            subkeyData.curve = .Secp256k1
        }
        let generateKeyData = GenerateKeyData(name: meta.name ?? "", email: meta.email ?? "", password: password,
                                              masterKey: masterkeyData, subkey: subkeyData)

        try self.init(generateKeyData: generateKeyData)
    }

}
