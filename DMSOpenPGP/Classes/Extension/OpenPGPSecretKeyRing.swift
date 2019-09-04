//
//  OpenPGPSecretKeyRing.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-19.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension BCOpenpgpPGPSecretKeyRing {

    public func verify(password: String) -> Bool {
        return getSigningPrivateKey(password: password) != nil
    }

    /// Get signing secret key from secret key ring (locked)
    ///
    /// - Returns: secrect key for signing
    public func getSigningSecretKey() -> OrgBouncycastleOpenpgpPGPSecretKey? {
        guard let iterator = getSecretKeys() else {
            return nil
        }

        while iterator.hasNext() {
            guard let key = iterator.next() as? OrgBouncycastleOpenpgpPGPSecretKey, key.isSigningKey() else {
                continue
            }

            return key
        }

        return nil
    }

    /// Get signing private key from secret key ring (unlock use password)
    ///
    /// - Parameter password: password to decrypt key
    /// - Returns: decrypted private key for signing
    /// - Note: Do not store this key for safety
    ///         And you can use this mehod verify password
    public func getSigningPrivateKey(password: String) -> OrgBouncycastleOpenpgpPGPPrivateKey? {
        guard let signingKey = getSigningSecretKey() else {
            return nil
        }

        guard let decryptor = OrgBouncycastleOpenpgpOperatorJcajceJcePBESecretKeyDecryptorBuilder()
            .setProviderWith(OrgBouncycastleJceProviderBouncyCastleProvider.PROVIDER_NAME)?
            .build(with: IOSCharArray(nsString: password)) else {
            return nil
        }

        return try? ExceptionCatcher.catchException { () -> OrgBouncycastleOpenpgpPGPPrivateKey in
            return signingKey.extractPrivateKey(with: decryptor)
        } as? OrgBouncycastleOpenpgpPGPPrivateKey
    }

    /// Get decrypting secret key from secret key ring (locked)
    ///
    /// - Parameter keyID: hex represent ID for key
    /// - Returns: matched secret key
    public func getDecryptingSecretKey(keyID: String) -> OrgBouncycastleOpenpgpPGPSecretKey? {
        guard let keyID = keyID.toPGPKeyID else {
            assertionFailure()
            return nil
        }

        return getSecretKey(withLong: keyID)
    }

    /// Get decrypting private key from secret key ring (unlock use password)
    ///
    /// - Parameters:
    ///   - keyID: hex represent ID for key
    ///   - password: password for key ring
    /// - Returns: matched private key
    public func getDecryptingPrivateKey(keyID: String, password: String) -> BCOpenpgpPGPPrivateKey? {
        guard let secretKey = getDecryptingSecretKey(keyID: keyID) else {
            return nil
        }

        return secretKey.getEncryptingPrivateKey(password: password)
    }

    public func getDecryptingKeyIDs() -> [String] {
        guard let iterator = getSecretKeys() else {
            return []
        }

        var keyIDs = Set<String>()
        while iterator.hasNext() {
            guard let key = iterator.next() as? OrgBouncycastleOpenpgpPGPSecretKey else {
                continue
            }

            keyIDs.insert(key.keyID)
        }

        return Array(keyIDs)
    }

}
