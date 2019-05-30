//
//  DMSPGPDecryptor.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-22.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public class DMSPGPDecryptor {

    public let armoredMessage: String
    public let encryptingKeyIDs: [String]

    public let encryptedDataDict: [String: BCOpenpgpPGPPublicKeyEncryptedData]

    private(set) public var onePassSignatureList: BCOpenpgpPGPOnePassSignatureList?
    private(set) public var signatureList: BCOpenpgpPGPSignatureList?
    private(set) public var modificationTime: Date?

    public init(armoredMessage message: String) throws {
        self.armoredMessage = message

        let byteArray = IOSByteArray(nsData: Data(message.utf8))!
        let input = JavaIoByteArrayInputStream(byteArray: byteArray)
        guard let armoredInput = BCOpenpgpPGPUtil.getDecoderStream(with: input) as? BCBcpgArmoredInputStream else {
            throw DMSPGPError.notArmoredInput
        }
        defer {
            input.close()
            armoredInput.close()
        }

        // Get encrypted data list
        var encryptedDataList: BCOpenpgpPGPEncryptedDataList?
        do {
            let result = try ExceptionCatcher.catchException {
                let objectFactory = BCOpenpgpPGPObjectFactory(javaIoInputStream: armoredInput, with: BCOpenpgpOperatorJcajceJcaKeyFingerprintCalculator())

                var object = objectFactory.nextObject()
                while object != nil {
                    guard let list = object as? BCOpenpgpPGPEncryptedDataList else {
                        object = objectFactory.nextObject()
                        continue
                    }

                    return list
                }

                return nil
            }

            encryptedDataList = result as? BCOpenpgpPGPEncryptedDataList
        } catch {
            // continue decrypt if got encryptedDataList
        }

        guard let iterator = encryptedDataList?.iterator() else {
            throw DMSPGPError.invalidMessage
        }

        // Get encrypted data
        var keyIDs = Set<String>()
        var encryptedDataDict: [String: BCOpenpgpPGPPublicKeyEncryptedData] = [:]
        while iterator.hasNext() {
            guard let data = iterator.next() as? BCOpenpgpPGPPublicKeyEncryptedData else {
                continue
            }

            let keyID = String(fromPGPKeyID: data.getKeyID())
            
            keyIDs.insert(keyID)
            encryptedDataDict[keyID] = data
        }

        guard !keyIDs.isEmpty && !encryptedDataDict.isEmpty else {
            throw DMSPGPError.invalidMessage
        }

        self.encryptingKeyIDs = Array(keyIDs)
        self.encryptedDataDict = encryptedDataDict
    }

}

extension DMSPGPDecryptor {

    public func decrypt(secretKey: BCOpenpgpPGPSecretKey, password: String) throws -> String {
        guard let privateKey = secretKey.getEncryptingPrivateKey(password: password) else {
            throw DMSPGPError.invalidSecrectKeyPassword
        }

        return try decrypt(privateKey: privateKey, keyID: secretKey.keyID)
    }

    public func decrypt(privateKey: BCOpenpgpPGPPrivateKey, keyID: String) throws -> String {
        guard let encryptedData = encryptedDataDict[keyID] else {
            throw DMSPGPError.invalidPrivateKey
        }

        var literalData: BCOpenpgpPGPLiteralData?

        var message: String?

        guard let input = encryptedData.getDataStream(with: BCOpenpgpOperatorBcBcPublicKeyDataDecryptorFactory(bcOpenpgpPGPPrivateKey: privateKey)) else {
            throw DMSPGPError.invalidPrivateKey
        }
        defer {
            input.close()
        }
        var factory = BCOpenpgpPGPObjectFactory(javaIoInputStream: input, with: BCOpenpgpOperatorJcajceJcaKeyFingerprintCalculator())
        var object: Any? = try? ExceptionCatcher.catchException {
            return factory.nextObject()
        }
        while object != nil {
            switch object {
            case let data as BCOpenpgpPGPCompressedData:
                guard let dataStream = data.getStream() else {
                    throw DMSPGPError.internal
                }
                factory = SkipMarkerPGPObjectFactory(javaIoInputStream: dataStream, with: BCOpenpgpOperatorJcajceJcaKeyFingerprintCalculator())
            case let list as BCOpenpgpPGPOnePassSignatureList:
                onePassSignatureList = list
            case let list as BCOpenpgpPGPSignatureList:
                signatureList = list
            case let data as BCOpenpgpPGPLiteralData:
                literalData = data
                message = {
                    guard let input = data.getInputStream() else { return nil }
                    let output = JavaIoByteArrayOutputStream()

                    BCUtilIoStreams.pipeAll(with: input, with: output)
                    output.close()
                    input.close()
                    return output.toString(with: "UTF-8")
                }()
            default:
                break
            }

            object = try? ExceptionCatcher.catchException {
                return factory.nextObject()
            }
        }

        if let modificationTime = literalData?.getModificationTime() {
            self.modificationTime = Date(javaUtilDate: modificationTime)
        }

        guard let result = message else {
            throw DMSPGPError.invalidMessage
        }

        return result.trimmingCharacters(in: .whitespacesAndNewlines)
    }

}

extension DMSPGPDecryptor {

    /// Verify armored message
    ///
    /// - Parameter message: armored message
    /// - Returns: true when valid armored message
    public static func verify(armoredMessage message: String) -> Bool {
        guard let byteArray = IOSByteArray(nsData: Data(message.utf8)) else {
            return false
        }

        let input = JavaIoByteArrayInputStream(byteArray: byteArray)
        guard let _ = BCOpenpgpPGPUtil.getDecoderStream(with: input) as? BCBcpgArmoredInputStream else {
            return false
        }

        return true
    }
}
