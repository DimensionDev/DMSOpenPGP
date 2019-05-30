//
//  Data+toHexString.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-24.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation

extension Data {

    func toHexString() -> String {
        return map { String(format: "%02hhx", $0) }.joined()
    }

}
