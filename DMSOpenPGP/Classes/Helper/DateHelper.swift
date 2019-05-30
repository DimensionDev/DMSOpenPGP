//
//  DateHelper.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-29.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

extension Date {

    public init?(javaUtilDate: JavaUtilDate) {
        let formatter = JavaTextSimpleDateFormat(nsString: "yyyy-MM-dd'T'HH:mm:sssZ")

        guard let iso8601 = formatter.format(with: javaUtilDate),
        let date = ISO8601DateFormatter().date(from: iso8601) else {
            return nil
        }

        self = date
    }

}
