//
//  DMSPGPSignatureVerifier.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-19.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public class DMSPGPSignatureVerifier {

    public let message: String
    public var onePassSignatureList: BCOpenpgpPGPOnePassSignatureList?
    public var signatureList: BCOpenpgpPGPSignatureList?

    /// Key meta info for signature in list
    public var onePassSignatureListKeyInfos: [DMSPGPKeyInfo] {
        guard let iterator = onePassSignatureList?.iterator() else { return [] }

        var infos: [DMSPGPKeyInfo] = []
        while iterator.hasNext() {
            let object = iterator.next()
            guard let signature = object as? BCOpenpgpPGPOnePassSignature else {
                continue
            }

            let keyID = String(fromPGPKeyID: signature.getKeyID())
            let info = DMSPGPKeyInfo(keyID: keyID, primaryUserID: nil)
            infos.append(info)
        }

        return infos
    }

    public var signatureListKeyInfos: [DMSPGPKeyInfo] {
        guard let iterator = signatureList?.iterator() else { return [] }

        var infos: [DMSPGPKeyInfo] = []
        while iterator.hasNext() {
            let object = iterator.next()
            guard let signature = object as? BCOpenpgpPGPSignature else {
                continue
            }

            let signatureSubpacket = signature.getHashedSubPackets() ?? signature.getUnhashedSubPackets()
            let userID = signatureSubpacket?.getSignerUserID()
            let keyID = String(fromPGPKeyID: signature.getKeyID())
            let info = DMSPGPKeyInfo(keyID: keyID, primaryUserID: userID)
            infos.append(info)
        }

        return infos
    }

    public init(message: String, onePassSignatureList: BCOpenpgpPGPOnePassSignatureList?, signatureList: BCOpenpgpPGPSignatureList?) {
        self.message = message.trimmingCharacters(in: .whitespacesAndNewlines)
        self.onePassSignatureList = onePassSignatureList
        self.signatureList = signatureList
    }

}

extension DMSPGPSignatureVerifier {

    public enum VerifyResult {
        case noSignature
        case valid
        case invalid
        case unknownSigner([DMSPGPKeyInfo])    // unknown signer
    }

    public func verifySignature(use publicKeyRing: BCOpenpgpPGPPublicKeyRing) -> VerifyResult {
        guard let signatureList = signatureList, !signatureList.isEmpty(),
        !signatureListKeyInfos.isEmpty else {
            return .noSignature
        }

        guard let signatureKey = publicKeyRing.primarySignatureKey else {
            return VerifyResult.unknownSigner(signatureListKeyInfos)
        }

        guard let iterator = signatureList.iterator() else {
            return .noSignature
        }

        while iterator.hasNext() {
            guard let signature = iterator.next() as? BCOpenpgpPGPSignature,
            signatureKey.keyID == signature.keyID else {
                continue
            }

            let builderProvider = BCOpenpgpOperatorJcajceJcaPGPContentVerifierBuilderProvider()
                .setProviderWith(BCJceProviderBouncyCastleProvider.PROVIDER_NAME)
            signature.init__(with: builderProvider, with: signatureKey)
            signature.update(with: IOSByteArray(nsData: Data(message.utf8)))
            signature.update(with: IOSByteArray(nsData: Data("\r\n".utf8)))
            if signature.verify() {
                return .valid
            }
        }

        return .invalid
    }

}

