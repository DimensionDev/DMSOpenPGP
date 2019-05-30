//
//  AppDelegate.swift
//  DMSOpenPGP
//
//  Created by CMK on 05/30/2019.
//  Copyright (c) 2019 CMK. All rights reserved.
//

import UIKit
import BouncyCastle_ObjC

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {

    var window: UIWindow?


    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

        // Add provider before use DMSOpenPGP (also add to extension if have)
        JavaSecuritySecurity.addProvider(with: BCJceProviderBouncyCastleProvider())

        return true
    }

}

