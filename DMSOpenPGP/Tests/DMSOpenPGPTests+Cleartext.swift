//
//  DMSOpenPGPTests+Cleartext.swift
//  TesserCubeTests
//
//  Created by Cirno MainasuK on 2019-5-8.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import XCTest
import BouncyCastle_ObjC
import DMSOpenPGP

class DMSOpenPGPTests_Cleartext: XCTestCase {

    override class func setUp() {
        JavaSecuritySecurity.addProvider(with: OrgBouncycastleJceProviderBouncyCastleProvider())
    }

    func testCleartext() {
        let keyRing = DMSOpenPGPTests.RSA
        let password = "RSA"

        let signer = try! DMSPGPSigner(secretKeyRing: keyRing.secretKeyRing!, password: password)
        let cleartext = signer.sign(message: "Message")

        print(cleartext)

        let cleartextVerifier = try! DMSPGPClearTextVerifier(cleartext: cleartext)
        let signatureVerifier = cleartextVerifier.signatureVerifier

        let message = cleartextVerifier.message
        print(message)
        XCTAssertEqual(message, "Message")

        let verifyResult = signatureVerifier.verifySignature(use: keyRing.publicKeyRing)
        guard case .valid = verifyResult else {
            XCTFail("\(verifyResult)")
            return
        }
    }

}

