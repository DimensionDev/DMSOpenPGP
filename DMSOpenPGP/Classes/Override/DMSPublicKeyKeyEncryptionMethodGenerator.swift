//
//  DMSPublicKeyKeyEncryptionMethodGenerator.swift
//  DMSOpenPGP
//
//  Created by jk234ert on 2019/6/11.
//

import Foundation
import BouncyCastle_ObjC

public class DMSPublicKeyKeyEncryptionMethodGenerator: BCOpenpgpOperatorBcBcPublicKeyKeyEncryptionMethodGenerator {
    
    var pubKey: BCOpenpgpPGPPublicKey
    
    public override init(bcOpenpgpPGPPublicKey key: BCOpenpgpPGPPublicKey!) {
        pubKey = key
        super.init(bcOpenpgpPGPPublicKey: key)
    }
    
    public override func generate(with encAlgorithm: jint, with sessionInfo: IOSByteArray!) -> BCBcpgContainedPacket! {
        return BCBcpgPublicKeyEncSessionPacket(long: 0, with: pubKey.getAlgorithm(), withByteArray2: processSessionInfo(with: encryptSessionInfo(with: pubKey, with: sessionInfo)))
    }
}
