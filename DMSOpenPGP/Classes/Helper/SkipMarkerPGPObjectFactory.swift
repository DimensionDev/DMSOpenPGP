//
//  SkipMarkerPGPObjectFactory.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-24.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public class SkipMarkerPGPObjectFactory: BCOpenpgpPGPObjectFactory {

    override public func nextObject() -> Any! {
        var nextObject = super.nextObject()

        while nextObject != nil && nextObject is BCOpenpgpPGPMarker {
            nextObject = super.nextObject()
        }

        return nextObject
    }

}
