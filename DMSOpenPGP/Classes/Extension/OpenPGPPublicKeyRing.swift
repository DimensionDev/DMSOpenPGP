//
//  OpenPGPPublicKeyRing.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-22.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension BCOpenpgpPGPPublicKeyRing {

    public var primaryKey: BCOpenpgpPGPPublicKey {
        return getPublicKey()
    }

    public var primarySignatureKey: BCOpenpgpPGPPublicKey? {
        guard let iterator = getPublicKeys() else {
            return nil
        }

        while iterator.hasNext() {
            guard let key = iterator.next() as? BCOpenpgpPGPPublicKey,
            key.isMasterKey() else {
                continue
            }

            return key
        }

        return nil
    }

    public var primaryEncryptionKey: BCOpenpgpPGPPublicKey? {
        return encryptionKeys.first
    }

    public var encryptionKeys: [BCOpenpgpPGPPublicKey] {
        guard let iterator = getPublicKeys() else {
            return []
        }

        var keys: [BCOpenpgpPGPPublicKey] = []
        while iterator.hasNext() {
            guard let key = iterator.next() as? BCOpenpgpPGPPublicKey, key.isEncryptionKey() else {
                continue
            }
            if key.isMasterKey() {
                // Append master key as the last choice
                keys.append(key)
            } else {
                // If we find a non-master encryption key, insert it as the first choice
                keys.insert(key, at: 0)
            }
        }

        return keys
    }

    public func getPublicKey(withKeyID keyID: String) -> BCOpenpgpPGPPublicKey? {
        guard let keyID = keyID.toPGPKeyID else {
            assertionFailure()
            return nil
        }

        return getPublicKey(withLong: keyID)
    }

}
