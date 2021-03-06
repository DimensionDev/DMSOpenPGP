//
//  DMSArmoredOutputStream.swift
//  TesserCube
//
//  Created by jk234ert on 2019/5/5.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

public struct DMSPGPArmoredHeader {
    public static let versionHeader = "Version"
    public static var versionHeaderContent: String? = nil

    public static let commentHeader = "Comment"
    public static var commentHeaderContentForArmoredKey = "Generated by DMSOpenPGP"
    public static var commentHeaderContentForMessage = "Encrypted by DMSOpenPGP"
}

open class DMSArmoredOutputStream: BCBcpgArmoredOutputStream {
    override public init(javaIoOutputStream outArg: JavaIoOutputStream!) {
        super.init(javaIoOutputStream: outArg)
        
        // Set nil to remove origin `version` header
        setHeaderWith(DMSPGPArmoredHeader.versionHeader, with: nil)
    }
    
    override public init(javaIoOutputStream outArg: JavaIoOutputStream!, with headers: JavaUtilHashtable!) {
        super.init(javaIoOutputStream: outArg, with: headers)
        
        // Set nil to remove origin `version` header
        setHeaderWith(DMSPGPArmoredHeader.versionHeader, with: nil)
    }
}

open class TCMessageArmoredOutputStream: DMSArmoredOutputStream {
    override public init(javaIoOutputStream outArg: JavaIoOutputStream!) {
        super.init(javaIoOutputStream: outArg)
        setHeaderWith(DMSPGPArmoredHeader.commentHeader, with: DMSPGPArmoredHeader.commentHeaderContentForMessage)
    }
    
    override public init(javaIoOutputStream outArg: JavaIoOutputStream!, with headers: JavaUtilHashtable!) {
        super.init(javaIoOutputStream: outArg, with: headers)
        setHeaderWith(DMSPGPArmoredHeader.commentHeader, with: DMSPGPArmoredHeader.commentHeaderContentForMessage)
    }
}

open class TCKeyArmoredOutputStream: DMSArmoredOutputStream {
    override public init(javaIoOutputStream outArg: JavaIoOutputStream!) {
        super.init(javaIoOutputStream: outArg)
        setHeaderWith(DMSPGPArmoredHeader.commentHeader, with: DMSPGPArmoredHeader.commentHeaderContentForArmoredKey)
    }
    
    override public init(javaIoOutputStream outArg: JavaIoOutputStream!, with headers: JavaUtilHashtable!) {
        super.init(javaIoOutputStream: outArg, with: headers)
        setHeaderWith(DMSPGPArmoredHeader.commentHeader, with: DMSPGPArmoredHeader.commentHeaderContentForArmoredKey)
    }
}
