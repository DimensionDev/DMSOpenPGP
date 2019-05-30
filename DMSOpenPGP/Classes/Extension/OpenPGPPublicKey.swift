//
//  OpenPGPPublicKey.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-24.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension BCOpenpgpPGPPublicKey {
    /// hex BCOpenPGP KeyID
    public var keyID: String {
        return String(fromPGPKeyID: getID())
    }
    
    /// lower 16 hex of fingerprint
    public var longIdentifier: String {
        return String(fingerprint.suffix(16))
    }
    
    /// lower 8 hex of fingerprint
    public var shortIdentifier: String {
        return String(fingerprint.suffix(8))
    }
}

extension BCOpenpgpPGPPublicKey {
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
}

extension BCOpenpgpPGPPublicKey {
    public var fingerprint: String {
        guard let rawFingerprint = getFingerprint().toNSData(), rawFingerprint.count == 20 else {
            fatalError()
        }

        return rawFingerprint.toHexString().uppercased()
    }
}

extension BCOpenpgpPGPPublicKey {
    public var keyStrength: Int {
        return Int(getBitStrength())
    }

    public var algorithm: DMSPGPPublicKeyAlgorithm {
        return DMSPGPPublicKeyAlgorithm(algorithm: getAlgorithm())
    }
}

extension BCOpenpgpPGPPublicKey {
    public var creationDate: Date? {
        guard let creationTime = getCreationTime() else {
            return nil
        }

        return Date(javaUtilDate: creationTime)
    }
    
    public var expireDate: Date? {
        guard let creationDate = creationDate else {
            return nil
        }
        if getValidSeconds() == 0 {
            // Zero valid seconds means no expiry
            return nil
        }
        
        return creationDate.addingTimeInterval(TimeInterval(getValidSeconds()))
    }
    
    public var isValid: Bool {
        guard let expireDate = expireDate else {
            // No expiry means key is always valid
            return true
        }
        return Date() <= expireDate
    }
}
