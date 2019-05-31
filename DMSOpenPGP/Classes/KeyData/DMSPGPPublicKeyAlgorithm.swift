//
//  DMSPGPPublicKeyAlgorithm.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-24.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

// Wrapper for org.bouncycastle.bcpg.PublicKeyAlgorithmTags
public enum DMSPGPPublicKeyAlgorithm {
    case RSA_GENERAL      // RSA (Encrypt or Sign)
    case RSA_ENCRYPT      // RSA Encrypt-Only
    case RSA_SIGN         // RSA Sign-Only
    case ELGAMAL_ENCRYPT  // Elgamal (Encrypt-Only), see [ELGAMAL]
    case DSA              // DSA (Digital Signature Standard)
    
    // case EC @deprecated use ECDH
    case ECDH             // Reserved for Elliptic Curve (actual algorithm name)
    case ECDSA            // Reserved for ECDSA
    case ELGAMAL_GENERAL  // Elgamal (Encrypt or Sign)
    case DIFFIE_HELLMAN   // Reserved for Diffie-Hellman (X9.42, as defined for IETF-S/MIME)
    case EDDSA            // EdDSA - (internet draft, but appearing in use)
    
    case EXPERIMENTAL_1
    case EXPERIMENTAL_2
    case EXPERIMENTAL_3
    case EXPERIMENTAL_4
    case EXPERIMENTAL_5
    case EXPERIMENTAL_6
    case EXPERIMENTAL_7
    case EXPERIMENTAL_8
    case EXPERIMENTAL_9
    case EXPERIMENTAL_10
    case EXPERIMENTAL_11
    
    case unknown
    
    // swiftlint:disable cyclomatic_complexity
    public init(algorithm: jint) {
        switch algorithm {
        case BCBcpgPublicKeyAlgorithmTags.RSA_GENERAL: self = .RSA_GENERAL
        case BCBcpgPublicKeyAlgorithmTags.RSA_ENCRYPT: self = .RSA_ENCRYPT
        case BCBcpgPublicKeyAlgorithmTags.RSA_SIGN: self = .RSA_SIGN
        case BCBcpgPublicKeyAlgorithmTags.ELGAMAL_ENCRYPT: self = .ELGAMAL_ENCRYPT
        case BCBcpgPublicKeyAlgorithmTags.DSA: self = .DSA
            
        case BCBcpgPublicKeyAlgorithmTags.ECDH: self = .ECDH
        case BCBcpgPublicKeyAlgorithmTags.ECDSA: self = .ECDSA
        case BCBcpgPublicKeyAlgorithmTags.ELGAMAL_GENERAL: self = .ELGAMAL_GENERAL
        case BCBcpgPublicKeyAlgorithmTags.DIFFIE_HELLMAN: self = .DIFFIE_HELLMAN
        case BCBcpgPublicKeyAlgorithmTags.EDDSA: self = .EDDSA
            
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_1: self = .EXPERIMENTAL_1
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_2: self = .EXPERIMENTAL_2
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_3: self = .EXPERIMENTAL_3
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_4: self = .EXPERIMENTAL_4
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_5: self = .EXPERIMENTAL_5
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_6: self = .EXPERIMENTAL_6
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_7: self = .EXPERIMENTAL_7
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_8: self = .EXPERIMENTAL_8
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_9: self = .EXPERIMENTAL_9
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_10: self = .EXPERIMENTAL_10
        case BCBcpgPublicKeyAlgorithmTags.EXPERIMENTAL_11: self = .EXPERIMENTAL_11
        default:
            self = .unknown
        }
        // swiftlint:enable cyclomatic_complexity
    }
    
    public var displayName: String {
        switch self {
        case .RSA_GENERAL,
             .RSA_SIGN,
             .RSA_ENCRYPT:
            return "RSA"
        case .ELGAMAL_GENERAL,
             .ELGAMAL_ENCRYPT:
            return "Elgamal"
        case .DSA:
            return "DSA"
        case .ECDH:
            return "EC"
        case .ECDSA:
            return "ECDSA"
        case .DIFFIE_HELLMAN:
            return "Diffie-Hellman"
        case .EDDSA:
            return "EdDSA"
        case .EXPERIMENTAL_1,
             .EXPERIMENTAL_2,
             .EXPERIMENTAL_3,
             .EXPERIMENTAL_4,
             .EXPERIMENTAL_5,
             .EXPERIMENTAL_6,
             .EXPERIMENTAL_7,
             .EXPERIMENTAL_8,
             .EXPERIMENTAL_9,
             .EXPERIMENTAL_10,
             .EXPERIMENTAL_11:
            return "Experimental"
        case .unknown:
            return "Unknown"
        }
    }
    
    public var supportKeyLength: [Int] {
        switch self {
        case .RSA_GENERAL,
             .RSA_SIGN,
             .RSA_ENCRYPT:
            return [2048, 3072, 4096]
        default:
            return []
        }
    }
}

public enum DMSPGPKeyCurve {
    case NIST_P256
    case NIST_P384
    case NIST_P521
    case Secp256k1
    
    public var parameterSpecName: String {
        switch self {
        case .NIST_P256:
            return "P-256"
        case .NIST_P384:
            return "P-384"
        case .NIST_P521:
            return "P-521"
        case .Secp256k1:
            return "secp256k1"
        }
    }
}
