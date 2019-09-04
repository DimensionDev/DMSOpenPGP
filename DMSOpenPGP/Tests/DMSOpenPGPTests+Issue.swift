//
//  DMSOpenPGPTests+Issue.swift
//  DMSOpenPGP-Unit-Tests
//
//  Created by Cirno MainasuK on 2019-7-18.
//

import XCTest
import BouncyCastle_ObjC
import DMSOpenPGP

class DMSOpenPGPTests_Issue: XCTestCase {

    override class func setUp() {
        JavaSecuritySecurity.addProvider(with: OrgBouncycastleJceProviderBouncyCastleProvider())
    }

    // fix crash for some input message: like "google"
    func testIssue_2() {
        let message = "google"
        let result = DMSPGPDecryptor.verify(armoredMessage: message)

        // should not crash and result equal false
        XCTAssertFalse(result)
    }

    func testIssue_3() {
        let alice = DMSOpenPGPTests.alice
        let secretKeyArmored = alice.secretKeyRing?.armored()
        XCTAssertNotNil(secretKeyArmored)

        // should throw error not crash
        var final: Error?
        do {
            _ = try DMSPGPKeyRing(armoredKey: secretKeyArmored!, password: "Wrong Password")
        } catch {
            final = error
        }
        XCTAssertNotNil(final)
    }

}
