//
//  KeyPairGenerator.swift
//  TesserCube
//
//  Created by jk234ert on 2019/5/14.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

class KeyPairGeneratorUtil {
    class func createKey(keyData: KeyData, createTime: JavaUtilDate) throws -> BCOpenpgpPGPKeyPair {
        if keyData.algorithm == .ECDH || keyData.algorithm == .ECDSA {
            guard keyData.curve != nil else { throw DMSPGPError.invalidCurve }
        }
        if keyData.algorithm != .EDDSA {
            guard keyData.strength >= 2048 else { throw DMSPGPError.invalidKeyLength }
        }
        
        var algorithm: jint
        var keyGen: JavaSecurityKeyPairGenerator
        
        switch keyData.algorithm {
        case .ELGAMAL_ENCRYPT,
             .ELGAMAL_GENERAL:
            keyGen = JavaSecurityKeyPairGenerator.getInstanceWith("ElGamal", with: BCJceProviderBouncyCastleProvider.PROVIDER_NAME)
            let p = Primes.getBestPrime(keySize: keyData.strength)
            let g = JavaMathBigInteger(nsString: "2")
            let elParams = OrgBouncycastleJceSpecElGamalParameterSpec(javaMathBigInteger: p, with: g)
            keyGen.initialize__(with: elParams)
            algorithm = BCBcpgPublicKeyAlgorithmTags.ELGAMAL_ENCRYPT
        case .RSA_ENCRYPT,
             .RSA_SIGN,
             .RSA_GENERAL:
            let keyPairGenerator = BCCryptoGeneratorsCryptoRSAKeyPairGenerator()
            let rsaKeyPair = generateKeypairWithOpenSSL(generator: keyPairGenerator, strength: keyData.strength)
            return BCOpenpgpOperatorBcBcPGPKeyPair(int: BCBcpgPublicKeyAlgorithmTags.RSA_GENERAL, with: rsaKeyPair, with: createTime)
        case .ECDSA:
            let ecParamSpec = getEccParameterSpec(curve: keyData.curve!)
            keyGen = JavaSecurityKeyPairGenerator.getInstanceWith("ECDSA", with: BCJceProviderBouncyCastleProvider.PROVIDER_NAME)
            keyGen.initialize__(with: ecParamSpec, with: JavaSecuritySecureRandom())
            algorithm = BCBcpgPublicKeyAlgorithmTags.ECDSA
        default:
            throw DMSPGPError.notSupportAlgorithm(keyData.algorithm)
        }
        return BCOpenpgpOperatorJcajceJcaPGPKeyPair(int: algorithm, with: keyGen.generateKeyPair(), with: createTime)
    }
    
    private class func generateKeypairWithOpenSSL(generator: BCCryptoGeneratorsCryptoRSAKeyPairGenerator, strength: Int) -> OrgBouncycastleCryptoAsymmetricCipherKeyPair? {
        let material = OpenSSLHelper.generateKeyMPI(Int32(strength), exponent: 0x10001)
        let bigN = JavaMathBigInteger(nsString: material.nDecString)
        let bigE = JavaMathBigInteger(nsString: material.eDecString)
        let bigD = JavaMathBigInteger(nsString: material.dDecString)
        let bigQ = JavaMathBigInteger(nsString: material.qDecString)
        let bigP = JavaMathBigInteger(nsString: material.pDecString)
        let bigDP = bigP.remainder(with: bigP.subtract(with: JavaMathBigInteger.ONE))
        let bigDQ = bigQ.remainder(with: bigQ.subtract(with: JavaMathBigInteger.ONE))
        let bigQINV = bigQ.modInverse(with: bigP)
        
        let keyParams = BCCryptoParamsRSAKeyParameters(boolean: false, with: bigN, with: bigE)
        let privateCrtKeyParams = BCCryptoParamsRSAPrivateCrtKeyParameters(javaMathBigInteger: bigN, with: bigE, with: bigD, with: bigP, with: bigQ, with: bigDP, with: bigDQ, with: bigQINV)
        
        let keypair = generator.generateKeyPair(with: keyParams, with: privateCrtKeyParams)
        return keypair
    }
    
    private class func getEccParameterSpec(curve: DMSPGPKeyCurve) -> JavaSecuritySpecECGenParameterSpec {
        return JavaSecuritySpecECGenParameterSpec(nsString: curve.parameterSpecName)
    }
}
