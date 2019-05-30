//
//  DMSOpenPGPTests+HiddenRecipients.swift
//  TesserCubeTests
//
//  Created by Cirno MainasuK on 2019-5-9.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import XCTest
import BouncyCastle_ObjC
import DMSOpenPGP
import ConsolePrint

class DMSOpenPGPTests_HiddenRecipients: XCTestCase {

    override class func setUp() {
        JavaSecuritySecurity.addProvider(with: OrgBouncycastleJceProviderBouncyCastleProvider())
    }

    func testCheckRecipients() {
        let decryptor = try! DMSPGPDecryptor(armoredMessage: message)
        consolePrint(decryptor.encryptedDataDict)
    }

}

private let message = """
-----BEGIN PGP MESSAGE-----

hH4DAAAAAAAAAAASAgMECARcH2/pSm7AzYlXj1e2AySoM4C6JoF1UAR4Ot6MfIaM
M7GVwRi41PdqIA4dsp98B6kxyV3HUv01RA2fBgx9FTA2t0RVFm44rr4Mett6QUTg
31eFJsFpjJ5sJzcaP69NE+mu13M9+GumNOM59/rcakjSQQFvhZD1yNgHtWpQmMu7
ZgrPJ/IDy+7tc3QuQkPzK/zg1oPAvIq5PGW90LS1MVtjBGXwsQ2hUdFdHVZ1paSb
IDEG
=Dv1Y
-----END PGP MESSAGE-----
"""
