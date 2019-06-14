//
//  DMSPGPEncryptor.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-19.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public class DMSPGPEncryptor {
    
    /// PublicKeyRing wrapper with isHidden option
    public struct PublicKeyData {
        public let publicKeyRing: BCOpenpgpPGPPublicKeyRing
        public let isHidden: Bool
        
        public init(publicKeyRing: BCOpenpgpPGPPublicKeyRing, isHidden: Bool = false) {
            self.publicKeyRing = publicKeyRing
            self.isHidden = isHidden
        }
    }
    
    public let publicKeyDataList: [PublicKeyData]

    // Use secret key ring for signature, varify password if valid or not when init Signer
    public let secretKeyRing: BCOpenpgpPGPSecretKeyRing?
    let password: String?
    public var compressAlgorithm = BCBcpgCompressionAlgorithmTags.ZIP

    public var encryptedDataGenerator: BCOpenpgpPGPEncryptedDataGenerator? {
        guard !publicKeyDataList.isEmpty else { return nil }
        guard let builder = BCOpenpgpOperatorJcajceJcePGPDataEncryptorBuilder(int: BCBcpgSymmetricKeyAlgorithmTags.AES_256)
            .setWithIntegrityPacketWithBoolean(true)?
            .setProviderWith(BCJceProviderBouncyCastleProvider.PROVIDER_NAME) else {
            return nil
        }
        let generator = BCOpenpgpPGPEncryptedDataGenerator(bcOpenpgpOperatorPGPDataEncryptorBuilder: builder)
        for publicKeyData in publicKeyDataList {
            // TODO: should use all encryption key here but not primary key. decrypt vice versa
            guard let encryptionKey = publicKeyData.publicKeyRing.primaryEncryptionKey else { continue }
            if publicKeyData.isHidden {
                let anonymousMethodGenerator = DMSPublicKeyKeyEncryptionMethodGenerator(bcOpenpgpPGPPublicKey: encryptionKey)
                generator.addMethod(with: anonymousMethodGenerator)
            } else {
                let keyEncryptionMathodGenerator = BCOpenpgpOperatorBcBcPublicKeyKeyEncryptionMethodGenerator(bcOpenpgpPGPPublicKey: encryptionKey)
                generator.addMethod(with: keyEncryptionMathodGenerator)
            }
        }
        return generator
    }

    public var signer: DMSPGPSigner?

    /// Encrypt without signature
    ///
    /// - Parameter publicKeyDataList: `PublicKeyData` with public key ring collection for encrypt and an `isHidden` option
    public init(publicKeyDataList: @autoclosure () -> [PublicKeyData]) throws {
        let publicKeyDataList = publicKeyDataList()
        guard !publicKeyDataList.isEmpty else {
            throw DMSPGPError.invalidPublicKeyRing
        }
        let invalidPublicKeyRings = publicKeyDataList.map { $0.publicKeyRing }.filter { $0.primaryEncryptionKey == nil }
        guard invalidPublicKeyRings.isEmpty else {
            throw DMSPGPError.missingEncryptionKey(keyRings: invalidPublicKeyRings)
        }

        self.publicKeyDataList = publicKeyDataList
        self.secretKeyRing = nil
        self.password = nil
    }

    /// Encrypt without signature
    ///
    /// - Parameter publicKeyRings: public key ring collection for encrypt
    /// - alsosee: `init(publicKeyDataList:)`
    public convenience init(publicKeyRings: [BCOpenpgpPGPPublicKeyRing]) throws {
        let publicKeyDataList = publicKeyRings.map { PublicKeyData(publicKeyRing: $0) }
        try self.init(publicKeyDataList: publicKeyDataList)
    }

    /// Encrypt with signature 
    ///
    /// - Parameters:
    ///   - publicKeyDataList: `PublicKeyData` with public key ring collection for encrypt and an `isHidden` option
    ///   - secretKeyRing: secret key ring for signature
    ///   - password: password for secret key ring
    public init(publicKeyDataList: @autoclosure () -> [PublicKeyData], secretKeyRing: BCOpenpgpPGPSecretKeyRing, password: String) throws {
        let publicKeyDataList = publicKeyDataList()
        let invalidPublicKeyRings = publicKeyDataList.map { $0.publicKeyRing }.filter { $0.primaryEncryptionKey === nil }
        guard invalidPublicKeyRings.isEmpty else {
            throw DMSPGPError.missingEncryptionKey(keyRings: invalidPublicKeyRings)
        }
        self.publicKeyDataList = publicKeyDataList
        self.secretKeyRing = secretKeyRing
        self.password = password
        self.signer = try DMSPGPSigner(secretKeyRing: secretKeyRing, password: password)
    }

    /// Encrypt with signature
    ///
    /// - Parameters:
    ///   - publicKeyRings: public key ring collection for encrypt
    ///   - secretKeyRing: secret key ring for signature
    ///   - password: password for secret key ring
    public convenience init(publicKeyRings: [BCOpenpgpPGPPublicKeyRing], secretKeyRing: BCOpenpgpPGPSecretKeyRing, password: String) throws {
        let publicKeyDataList = publicKeyRings.map { PublicKeyData(publicKeyRing: $0) }
        try self.init(publicKeyDataList: publicKeyDataList, secretKeyRing: secretKeyRing, password: password)
    }

    /// Clearsign without encrypt
    ///
    /// - Parameters:
    ///   - secretKeyRing: secret key ring for signature
    ///   - password: password for private key
    public init(secretKeyRing: BCOpenpgpPGPSecretKeyRing, password: String) throws {
        self.publicKeyDataList = []
        self.secretKeyRing = secretKeyRing
        self.password = password
        self.signer = try DMSPGPSigner(secretKeyRing: secretKeyRing, password: password)
    }

}

extension DMSPGPEncryptor {

    /// Enrypt message use publicKeys and sign if possible
    /// Or only clearsign message without encrypt when no public keys
    ///
    /// - Parameter message: UTF-8 string
    /// - Returns: armored encrypted message
    public func encrypt(message: String) throws -> String {
        let message = message.trimmingCharacters(in: .whitespacesAndNewlines)
        let output = JavaIoByteArrayOutputStream()
        let armoredOutput = TCMessageArmoredOutputStream(javaIoOutputStream: output)

        let messageData = Data(message.utf8)
        let messageBytes = IOSByteArray(nsData: messageData)!

        let signer = self.signer

        switch (encryptedDataGenerator, signer) {
        // encrypt and sign if possiable
        case let (encryptedDataGenerator?, _):
            let encryptDate = JavaUtilDate()
            let encryptedOutput = encryptedDataGenerator.open(with: armoredOutput, with: IOSByteArray(length: 1 << 16))
            let compressedDataGenerator = BCOpenpgpPGPCompressedDataGenerator(int: compressAlgorithm)
            let bcpgOutputStream = encryptedOutput.flatMap { encryptedOutput -> BCBcpgBCPGOutputStream in
                guard compressAlgorithm != BCBcpgCompressionAlgorithmTags.UNCOMPRESSED else {
                    return BCBcpgBCPGOutputStream(javaIoOutputStream: encryptedOutput)
                }
                let compressedOutput = compressedDataGenerator.open(with: encryptedOutput)
                return BCBcpgBCPGOutputStream(javaIoOutputStream: compressedOutput)
            }

            guard let bcpgOutput = bcpgOutputStream else {
                compressedDataGenerator.close()
                encryptedOutput?.close()

                armoredOutput.close()
                output.close()
                throw DMSPGPError.internal
            }

            signer?.signatureGenerator.generateOnePassVersion(withBoolean: false)?.encode(with: bcpgOutput)

            let literalDataGenerator = BCOpenpgpPGPLiteralDataGenerator()
            guard let literalDataOutput = literalDataGenerator
                .open(with: bcpgOutput,
                      withChar: BCOpenpgpPGPLiteralData.UTF8,
                      with: BCOpenpgpPGPLiteralData.CONSOLE,
                      with: encryptDate,
                      with: IOSByteArray(length: 1 << 16)) else {
                literalDataGenerator.close()
                bcpgOutput.close()
                compressedDataGenerator.close()
                encryptedOutput?.close()

                armoredOutput.close()
                output.close()
                throw DMSPGPError.internal
            }

            literalDataOutput.write(with: messageBytes)
            literalDataOutput.write(with: IOSByteArray(nsData: Data("\r\n".utf8)))
            signer?.signatureGenerator.update(with: messageBytes)
            signer?.signatureGenerator.update(with: IOSByteArray(nsData: Data("\r\n".utf8)))
            literalDataOutput.close()
            signer?.signatureGenerator.generate()?.encode(with: literalDataOutput)

            bcpgOutput.close()
            compressedDataGenerator.close()
            encryptedOutput?.close()
            encryptedDataGenerator.close()

        // clear sign
        case let (nil, signer?):
            return signer.sign(message: message)
        default:
            throw DMSPGPError.internal
        }

        armoredOutput.close()
        output.close()

        return output.toString(with: "UTF-8")
    }

}
