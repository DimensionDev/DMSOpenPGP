//
//  DMSPGPKeyRingFactory.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-18.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public class DMSPGPKeyRingFactory {

    let keyRingGenerator: BCOpenpgpPGPKeyRingGenerator

    public var keyRing: DMSPGPKeyRing {
        return DMSPGPKeyRing(publicKeyRing: publicKeyRing, secretKeyRing: secretKeyRing)
    }

    public var publicKeyRing: BCOpenpgpPGPPublicKeyRing {
        return keyRingGenerator.generatePublicKeyRing()
    }

    public var secretKeyRing: BCOpenpgpPGPSecretKeyRing {
        return keyRingGenerator.generateSecretKeyRing()
    }

    /// Create PGP key ring
    ///
    /// - Parameter generateKeyData: key meta info (UserID, password e.t.c)
    public init(generateKeyData: GenerateKeyData) throws {
        guard let keyRingGenerator = DMSPGPKeyRingFactory.keyRingGenerator(generateKeyData: generateKeyData) else {
            throw DMSPGPError.internal
        }
        self.keyRingGenerator = keyRingGenerator
    }

}

extension DMSPGPKeyRingFactory {
    
    public static func keyRingGenerator(generateKeyData: GenerateKeyData) -> BCOpenpgpPGPKeyRingGenerator? {
        do {
            let userID = DMSPGPUserIDTranslator(name: generateKeyData.name, email: generateKeyData.email, comment: nil).userID
            let date = JavaUtilDate()
            let masterKey = try KeyPairGeneratorUtil.createKey(keyData: generateKeyData.masterKey, createTime: date)
            let subkey = try KeyPairGeneratorUtil.createKey(keyData: generateKeyData.subkey, createTime: date)
            let masterSignatureSubpacketGenerator: BCOpenpgpPGPSignatureSubpacketGenerator = {
                let signatureSubpacketGenerator = BCOpenpgpPGPSignatureSubpacketGenerator()
                
                signatureSubpacketGenerator.setKeyFlagsWithBoolean(false, with: BCBcpgSigKeyFlags.SIGN_DATA | BCBcpgSigKeyFlags.CERTIFY_OTHER)
                signatureSubpacketGenerator.setPreferredSymmetricAlgorithmsWithBoolean(false, with: IOSIntArray(ints: [
                    BCBcpgSymmetricKeyAlgorithmTags.AES_256,
                    BCBcpgSymmetricKeyAlgorithmTags.AES_192,
                    BCBcpgSymmetricKeyAlgorithmTags.AES_128,
                    ], count: 3))
                signatureSubpacketGenerator.setPreferredHashAlgorithmsWithBoolean(false, with: IOSIntArray(ints: [
                    BCBcpgHashAlgorithmTags.SHA256,
                    BCBcpgHashAlgorithmTags.SHA1,
                    BCBcpgHashAlgorithmTags.SHA384,
                    BCBcpgHashAlgorithmTags.SHA512,
                    BCBcpgHashAlgorithmTags.SHA224,
                    ], count: 5))
                signatureSubpacketGenerator.setFeatureWithBoolean(false, withByte: BCBcpgSigFeatures.FEATURE_MODIFICATION_DETECTION)
                
                return signatureSubpacketGenerator
            }()
            
            let subSignatureSubpacketGenerator: BCOpenpgpPGPSignatureSubpacketGenerator = {
                let signatureSubpacketGenerator = BCOpenpgpPGPSignatureSubpacketGenerator()
                signatureSubpacketGenerator.setKeyFlagsWithBoolean(false, with: BCBcpgSigKeyFlags.ENCRYPT_COMMS | BCBcpgSigKeyFlags.ENCRYPT_STORAGE)
                return signatureSubpacketGenerator
            }()
            
            let sha1Calculator = BCOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder().build()?.getWith(BCBcpgHashAlgorithmTags.SHA1)
            let sha256Calculator = BCOpenpgpOperatorJcajceJcaPGPDigestCalculatorProviderBuilder().build()?.getWith(BCBcpgHashAlgorithmTags.SHA256)
            
            guard let encryptor = BCOpenpgpOperatorJcajceJcePBESecretKeyEncryptorBuilder(int: BCBcpgSymmetricKeyAlgorithmTags.AES_256, with: sha256Calculator, with: 0x90)
                .setProviderWith(BCJceProviderBouncyCastleProvider.PROVIDER_NAME)
                .build(with: IOSCharArray(nsString: generateKeyData.password)) else {
                    assertionFailure()
                    return nil
            }
            
            guard let algorithm = masterKey.getPublicKey()?.getAlgorithm() else {
                assertionFailure()
                return nil
            }
            
            let keyRingGenerator =  BCOpenpgpPGPKeyRingGenerator(int: BCOpenpgpPGPSignature.POSITIVE_CERTIFICATION,
                                                                 with: masterKey,
                                                                 with: userID,
                                                                 with: sha1Calculator,
                                                                 with: masterSignatureSubpacketGenerator.generate(),
                                                                 with: nil,
                                                                 with: BCOpenpgpOperatorJcajceJcaPGPContentSignerBuilder(int: algorithm, with: BCBcpgHashAlgorithmTags.SHA512).setProviderWith(BCJceProviderBouncyCastleProvider.PROVIDER_NAME),
                                                                 with: encryptor)
            keyRingGenerator.addSubKey(with: subkey, with: subSignatureSubpacketGenerator.generate(), with: nil)
            return keyRingGenerator
        } catch let error {
            NSLog("%error: @", error.localizedDescription)
            return nil
        }
        
    }
}
