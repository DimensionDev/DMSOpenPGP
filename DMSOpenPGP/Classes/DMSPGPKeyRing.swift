//
//  DMSPGPKeyRing.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-24.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public struct DMSPGPKeyRing {

    public let publicKeyRing: BCOpenpgpPGPPublicKeyRing
    public let secretKeyRing: BCOpenpgpPGPSecretKeyRing?

    public init(armoredKey armored: String, password: String? = nil) throws {
        if let password = password {
            self.secretKeyRing = try DMSPGPKeyRing.secretKeyRing(from: armored, password: password)
        } else {
            // Delay password varify
            self.secretKeyRing = try? DMSPGPKeyRing.secretKeyRing(from: armored)
        }

        if let secretKeyRing = self.secretKeyRing {
            if let publicKeyRingFromArmored = try? DMSPGPKeyRing.publicKeyRing(from: armored) {
                self.publicKeyRing = publicKeyRingFromArmored
            } else {
                self.publicKeyRing = try DMSPGPKeyRing.publicKeyRing(from: secretKeyRing)
            }
        } else {
            self.publicKeyRing = try DMSPGPKeyRing.publicKeyRing(from: armored)
        }
    }

    public init(publicKeyRing: BCOpenpgpPGPPublicKeyRing, secretKeyRing: BCOpenpgpPGPSecretKeyRing? = nil) {
        self.publicKeyRing = publicKeyRing
        self.secretKeyRing = secretKeyRing
    }

    public init(secretKeyRing: BCOpenpgpPGPSecretKeyRing) throws {
        self.publicKeyRing = try DMSPGPKeyRing.publicKeyRing(from: secretKeyRing)
        self.secretKeyRing = secretKeyRing
    }

}

extension DMSPGPKeyRing {

    private static func keyRing<T: BCOpenpgpPGPKeyRing>(from armored: String) throws -> T {
        guard let byteArray = IOSByteArray(nsData: Data(armored.utf8)) else {
            throw DMSPGPError.internal
        }

        let input = JavaIoByteArrayInputStream(byteArray: byteArray)
        defer { input.close() }
        let armoredInput = BCBcpgArmoredInputStream(javaIoInputStream: input)
        defer { armoredInput.close() }

        let result = try? ExceptionCatcher.catchException {
            let objectFactory = BCOpenpgpPGPObjectFactory(javaIoInputStream: armoredInput, with: BCOpenpgpOperatorJcajceJcaKeyFingerprintCalculator())
            return objectFactory.nextObject() as? T
        }

        guard let keyRing = result as? T else {
            throw DMSPGPError.invalidArmored
        }

        return keyRing
    }

}

// MARK: - Public Key Ring
extension DMSPGPKeyRing {

    public static func publicKeyRing(from armored: String) throws -> BCOpenpgpPGPPublicKeyRing {
        guard let armoredPulibcKey = extractPublicKeyBlock(from: armored) else {
            throw DMSPGPError.invalidArmored
        }
        let publicKeyRing: BCOpenpgpPGPPublicKeyRing = try keyRing(from: armoredPulibcKey)
        return publicKeyRing
    }

    public static func publicKeyRing(from secretKeyRing: BCOpenpgpPGPSecretKeyRing) throws -> BCOpenpgpPGPPublicKeyRing {
        guard let iterator = secretKeyRing.getPublicKeys() else {
            throw DMSPGPError.invalidSecretKeyRing
        }

        var publicKeys: [BCOpenpgpPGPPublicKey] = []
        while iterator.hasNext() {
            guard let publicKey = iterator.next() as? BCOpenpgpPGPPublicKey else {
                continue
            }

            publicKeys.append(publicKey)
        }

        guard !publicKeys.isEmpty else {
            throw DMSPGPError.invalidSecretKeyRing
        }

        let arrayList = JavaUtilArrayList(int: jint(publicKeys.count))
        for key in publicKeys {
            arrayList.add(withId: key)
        }

        let publicKeyRing = BCOpenpgpPGPPublicKeyRing(javaUtilList: arrayList)

        return publicKeyRing
    }

    public static func extractPublicKeyBlock(from armored: String) -> String? {
        guard let header = armored.range(of: "-----BEGIN PGP PUBLIC KEY BLOCK-----"),
        let footer = armored.range(of: "-----END PGP PUBLIC KEY BLOCK-----") else {
            return nil
        }

        return String(armored[header.lowerBound..<footer.upperBound])
    }

}

// MARK: - Secret Key Ring
extension DMSPGPKeyRing {

    public static func secretKeyRing(from armored: String, password: String) throws -> BCOpenpgpPGPSecretKeyRing {
        guard let armoredSecretKey = extractSecretKeyBlock(from: armored) else {
            throw DMSPGPError.invalidArmored
        }
        let secrectKeyRing: BCOpenpgpPGPSecretKeyRing = try keyRing(from: armoredSecretKey)

        guard secrectKeyRing.verify(password: password) else {
            throw DMSPGPError.invalidSecrectKeyPassword
        }

        return secrectKeyRing
    }

    public static func secretKeyRing(from armored: String) throws -> BCOpenpgpPGPSecretKeyRing {
        guard let armoredSecretKey = extractSecretKeyBlock(from: armored) else {
            throw DMSPGPError.invalidArmored
        }
        let secrectKeyRing: BCOpenpgpPGPSecretKeyRing = try keyRing(from: armoredSecretKey)

        return secrectKeyRing
    }

    private enum SecretKeyHeader: String {
        case v1 = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        case v2 = "-----BEGIN PGP SECRET KEY BLOCK-----"
    }

    private enum SecretKeyFooter: String {
        case v1 = "-----END PGP PRIVATE KEY BLOCK-----"
        case v2 = "-----END PGP SECRET KEY BLOCK-----"
    }

    public static func extractSecretKeyBlock(from armored: String) -> String? {
        guard let header = armored.range(of: SecretKeyHeader.v1.rawValue) ?? armored.range(of: SecretKeyHeader.v2.rawValue),
        let footer = armored.range(of: SecretKeyFooter.v1.rawValue) ?? armored.range(of: SecretKeyFooter.v2.rawValue) else {
            return nil
        }

        return String(armored[header.lowerBound..<footer.upperBound])
    }

}
