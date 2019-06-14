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
        XCTAssertTrue(decryptor.encryptingKeyIDs.isEmpty)
        XCTAssertTrue(decryptor.encryptedDataDict.isEmpty)
        XCTAssertTrue(decryptor.hiddenRecipientsDataList.count == 1)
        consolePrint(decryptor.encryptedDataDict)
    }

    func testDecrypt() {
        let decryptor = try! DMSPGPDecryptor(armoredMessage: message)
        let RSA = DMSOpenPGPTests.RSA

        XCTAssertTrue(decryptor.encryptingKeyIDs.isEmpty)
        XCTAssertTrue(decryptor.encryptedDataDict.isEmpty)
        XCTAssertTrue(decryptor.hiddenRecipientsDataList.count == 1)

        var message = ""
        // Should check all possiable decrypt key due to unknown recipients
        // And it's could be skip if we have one
        for keyID in RSA.secretKeyRing?.getDecryptingKeyIDs() ?? [] {
            guard let decryptKey = RSA.secretKeyRing?.getDecryptingSecretKey(keyID: keyID) else {
                continue
            }

            do {
                let privateKey = decryptKey.getEncryptingPrivateKey(password: "RSA")
                message = try decryptor.decrypt(privateKey: privateKey!, encryptedData: decryptor.hiddenRecipientsDataList.first!)
                return
            } catch {
                consolePrint(error.localizedDescription)
                continue
            }
        }

        XCTAssertEqual(message, "This is one hidden recipients message.")
    }

}

// gpg --encrypt -R 'RSA@pgp.key' --armor message.txt
private let message = """
-----BEGIN PGP MESSAGE-----

hQIMAwAAAAAAAAAAAQ/9EdQi4zllEr1vN41mb+hPrKaTtBZqhuEGXTbzCrmZXLJd
OMwRKyVGGUhskNVzM31BUH5LA1TWihxxKzX41sPcCOM2RHFe6vv0w12sv8YHXv4q
MJ+WUC602lzfxokhkEsBCscqVdiB/e0Y/rR3+nsbK/mhwHhRgNAT9AOtWbeEp1GT
wBWkvfecqtwz2I20lTSybsF72Lbx3bH06n70WaUTQY0L5hBkYUhCGTtXzKmXOSnu
q3rfNgMywviGbw0QlQ0YPI1brdilCVsP6v/yh+vrjlTEs7+a8FWym6Zx7XDEx9nc
wIR+j2JhMtms9lhMfKeL1+GNHWmTjnCSCbWa2IaaVt/doAFPOgEqeeecPjt8JrQ9
PD6uy7aJ2+xTJqL1sta4s/iIIk5StB7hrm0z+UFIl1rmhbA8xKXeJbmjpf8z/tcz
n02DjIdI4lvgZfsDUDdsEGOW34CBYPsPHf1FlT1T7jFTGVWV/LiEcQWy7+P9+0bq
82BCw30B+lWCKsb6Td3z0dm8tDDoOqFz7JqNJWv4yJpXSx+4Kd3VIl7sTwjTYJaJ
vOfzs7BREK6RKr48huJktnJF0XTZI7iqUjQa5O4CWGTJXijbsQYc7KfE3REf2BFp
XNbUEvFF8yWN03mH6SMJHkewrUrIoGxWXoVbQh5VUMCirnsBe4VhqpXLYSEOmWjS
ZAHQ2vHXes2jZPwWaMDhpc6AJzepRRcEHzkImk9Pwd5rVV9gN5nXUjMR2CRasFns
hOha+b+TPwNzZo2hZsy+D0UYbnbT0kREKsL3YVTMVZ+DWhM6lLMwyqMTzK86ueK3
CYP/pUo=
=rSRm
-----END PGP MESSAGE-----
"""
