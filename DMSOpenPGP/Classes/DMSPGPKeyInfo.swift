//
//  DMSPGPKeyInfo.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-29.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

/// Note: - use raw KeyID to retrieve 
public struct DMSPGPKeyInfo {
    public let keyID: String
    public let primaryUserID: String?
}
