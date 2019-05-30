//
//  OpenPGPSecretKey.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-24.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension BCOpenpgpPGPSecretKey {

    /// hex BCOpenPGP keyID
    public var keyID: String {
        return String(fromPGPKeyID: getID())
    }

    public var primaryUserID: String? {
        return userIDs.first
    }

    public var userIDs: [String] {
        guard let iterator = getUserIDs() else {
            return []
        }

        var ids: [String] = []
        while iterator.hasNext() {
            guard let userID = iterator.next() as? String else { continue }
            ids.append(userID)
        }

        return ids
    }

    public func getEncryptingPrivateKey(password: String) -> BCOpenpgpPGPPrivateKey? {
        guard let decryptor = BCOpenpgpOperatorJcajceJcePBESecretKeyDecryptorBuilder()
            .setProviderWith(BCJceProviderBouncyCastleProvider.PROVIDER_NAME)?
            .build(with: IOSCharArray(nsString: password)) else {
                return nil
        }

        return try? ExceptionCatcher.catchException {
            return extractPrivateKey(with: decryptor)
        } as? BCOpenpgpPGPPrivateKey
    }
}
