//
//  GenerateKeyData.swift
//  TesserCube
//
//  Created by jk234ert on 2019/5/14.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation

public struct KeyData {
    public var strength: Int = 3072
    public var algorithm: DMSPGPPublicKeyAlgorithm = .RSA_GENERAL
    public var curve: DMSPGPKeyCurve?

    public init(strength: Int = 3072, algorithm: DMSPGPPublicKeyAlgorithm = .RSA_GENERAL, curve: DMSPGPKeyCurve? = nil) {
        self.strength = strength
        self.algorithm = algorithm
        self.curve = curve
    }
}

public struct GenerateKeyData {
    public var name: String
    public var email: String
    public var password: String
    public var masterKey: KeyData
    public var subkey: KeyData

    public init(name: String, email: String, password: String?, masterKey: KeyData, subkey: KeyData) {
        self.name = name
        self.email = email
        self.password = password ?? ""
        self.masterKey = masterKey
        self.subkey = subkey
    }
}
