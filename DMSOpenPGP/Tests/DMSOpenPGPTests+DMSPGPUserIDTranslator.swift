//
//  PGPUserIDTranslatorTests.swift
//  TesserCubeTests
//
//  Created by Cirno MainasuK on 2019-3-22.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import XCTest
import BouncyCastle_ObjC
import DMSOpenPGP
import ConsolePrint

class PGPUserIDTranslatorTests: XCTestCase {

    override class func setUp() {
        JavaSecuritySecurity.addProvider(with: OrgBouncycastleJceProviderBouncyCastleProvider())
    }

    func testBuildAndExtract() {
        let userID_1A = DMSPGPUserIDTranslator(name: "Name", email: nil, comment: nil)
        let userID_1B = DMSPGPUserIDTranslator(userID: "Name")
        XCTAssertEqual(userID_1A.userID, "Name")
        XCTAssertEqual(userID_1B.name, "Name")
        XCTAssertEqual(userID_1B.comment, nil)
        XCTAssertEqual(userID_1B.email, nil)

        let userID_2A = DMSPGPUserIDTranslator(name: "Name )", email: nil, comment: nil)
        let userID_2B = DMSPGPUserIDTranslator(userID: "Name )")
        XCTAssertEqual(userID_2A.userID, "Name ) ()")
        XCTAssertEqual(userID_2B.name, "Name )")
        XCTAssertEqual(userID_2B.comment, nil)
        XCTAssertEqual(userID_2B.email, nil)

        let userID_3A = DMSPGPUserIDTranslator(name: nil, email: "name@mail.com", comment: nil)
        let userID_3B = DMSPGPUserIDTranslator(userID: "name@mail.com")
        XCTAssertEqual(userID_3A.userID, "name@mail.com")
        XCTAssertEqual(userID_3B.name, nil)
        XCTAssertEqual(userID_3B.comment, nil)
        XCTAssertEqual(userID_3B.email, "name@mail.com")

        let userID_4A = DMSPGPUserIDTranslator(name: "Name", email: "name@mail.com", comment: nil)
        let userID_4B = DMSPGPUserIDTranslator(userID: "Name <name@mail.com>")
        XCTAssertEqual(userID_4A.userID, "Name <name@mail.com>")
        XCTAssertEqual(userID_4B.name, "Name")
        XCTAssertEqual(userID_4B.comment, nil)
        XCTAssertEqual(userID_4B.email, "name@mail.com")

        let userID_5A = DMSPGPUserIDTranslator(name: nil, email: "name@mail.com", comment: "Comment")
        let userID_5B = DMSPGPUserIDTranslator(userID: "(Comment) <name@mail.com>")
        XCTAssertEqual(userID_5A.userID, "(Comment) <name@mail.com>")
        XCTAssertEqual(userID_5B.name, nil)
        XCTAssertEqual(userID_5B.comment, "Comment")
        XCTAssertEqual(userID_5B.email, "name@mail.com")

        let userID_6A = DMSPGPUserIDTranslator(name: "Name", email: "name@mail.com", comment: "Comment")
        let userID_6B = DMSPGPUserIDTranslator(userID: "Name (Comment) <name@mail.com>")
        XCTAssertEqual(userID_6A.userID, "Name (Comment) <name@mail.com>")
        XCTAssertEqual(userID_6B.name, "Name")
        XCTAssertEqual(userID_6B.comment, "Comment")
        XCTAssertEqual(userID_6B.email, "name@mail.com")

        let userID_7A = DMSPGPUserIDTranslator(name: "Name )", email: "name@mail.com", comment: "Comment")
        let userID_7B = DMSPGPUserIDTranslator(userID: "Name ) (Comment) <name@mail.com>")
        XCTAssertEqual(userID_7A.userID, "Name ) (Comment) <name@mail.com>")
        XCTAssertEqual(userID_7B.name, "Name )")
        XCTAssertEqual(userID_7B.comment, "Comment")
        XCTAssertEqual(userID_7B.email, "name@mail.com")
    }

}
