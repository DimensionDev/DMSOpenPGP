//
//  DMSPGPSigner.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-19.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public class DMSPGPSigner {

    public let signatureGenerator: BCOpenpgpPGPSignatureGenerator
    public let signingAlgorithm: jint

    private let signingDate: JavaUtilDate

    public init(privateKey: BCOpenpgpPGPPrivateKey, signingAlgorithm: jint, userID: String) {
        let signingDate = JavaUtilDate()

        self.signatureGenerator = {
            let signerBuilder = BCOpenpgpOperatorBcBcPGPContentSignerBuilder(int: signingAlgorithm, with: BCBcpgHashAlgorithmTags.SHA512)
            let signatureGenerator = BCOpenpgpPGPSignatureGenerator(bcOpenpgpOperatorPGPContentSignerBuilder: signerBuilder)
            signatureGenerator.init__(with: BCOpenpgpPGPSignature.BINARY_DOCUMENT, with: privateKey)

            let signatureSubPacketGenerator = BCOpenpgpPGPSignatureSubpacketGenerator()
            signatureSubPacketGenerator.setSignerUserIDWithBoolean(false, with: userID)
            signatureSubPacketGenerator.setSignatureCreationTimeWithBoolean(false, with: signingDate)   // TODO: move to signing parse
            signatureGenerator.setHashedSubpacketsWith(signatureSubPacketGenerator.generate())

            return signatureGenerator
        }()
        self.signingAlgorithm = signingAlgorithm
        self.signingDate = signingDate
    }

    convenience public init(secretKeyRing: BCOpenpgpPGPSecretKeyRing, password: String) throws {
        guard let signingAlgorithm = secretKeyRing.getSigningSecretKey()?.getPublicKey()?.getAlgorithm(),
        let privateKey = secretKeyRing.getSigningPrivateKey(password: password),
        let userID = secretKeyRing.getPublicKey()?.getUserIDs()?.next() as? String else {
            throw DMSPGPError.invalidSecretKeyRing
        }

        self.init(privateKey: privateKey, signingAlgorithm: signingAlgorithm, userID: userID)
    }

}

extension DMSPGPSigner {

    /// Cleartext sign
    ///
    /// - Parameter message: message to sign
    /// - Returns: armored cleartext signature
    public func sign(message: String) -> String {
        let message = message.trimmingCharacters(in: .whitespacesAndNewlines)
        let output = JavaIoByteArrayOutputStream()
        let armoredOutput = TCMessageArmoredOutputStream(javaIoOutputStream: output)

        let messageData = Data(message.utf8)
        let messageBytes = IOSByteArray(nsData: messageData)!

        armoredOutput.beginClearText(with: BCBcpgHashAlgorithmTags.SHA512)
        armoredOutput.write(with: messageBytes)
        signatureGenerator.update(with: messageBytes)
        armoredOutput.write(with: IOSByteArray(nsData: Data("\r\n".utf8)))
        signatureGenerator.update(with: IOSByteArray(nsData: Data("\r\n".utf8)))
        armoredOutput.endClearText()
        let bcpgOutput = BCBcpgBCPGOutputStream(javaIoOutputStream: armoredOutput)
        signatureGenerator.generate()?.encode(with: bcpgOutput)
        bcpgOutput.close()
        armoredOutput.close()
        output.close()

        return output.toString(with: "UTF-8")
    }
}
