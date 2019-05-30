//
//  DMSOpenPGPTests+EmptyEncryptionKeyRecipient.swift
//  TesserCubeTests
//
//  Created by Cirno MainasuK on 2019-5-14.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import XCTest
import BouncyCastle_ObjC
import DMSOpenPGP
import ConsolePrint

class DMSOpenPGPTests_EmptyEncryptionKeyRecipient: XCTestCase {

    override class func setUp() {
        JavaSecuritySecurity.addProvider(with: BCJceProviderBouncyCastleProvider())
    }

    func testComposeMessage() {
        let recipient = try? DMSPGPKeyRing(armoredKey: emptyEncryptionKey)
        XCTAssertNotNil(recipient)

        var err: Error?
        do {
            let encryptor = try DMSPGPEncryptor(publicKeyRings: [recipient!.publicKeyRing])
            let encrypted = try encryptor.encrypt(message: "Message")
            consolePrint(encrypted)     // should not print anything
        } catch {
            err = error
            consolePrint(error.localizedDescription)
        }

        XCTAssertNotNil(err)
    }

}

fileprivate let emptyEncryptionKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=nmwR
-----END PGP PUBLIC KEY BLOCK-----
"""
