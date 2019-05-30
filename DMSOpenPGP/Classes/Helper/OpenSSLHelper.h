//
//  OpenSSLHelper.h
//  TesserCube
//
//  Created by jk234ert on 2019/4/25.
//  Copyright © 2019 Sujitech. All rights reserved.
//

#ifndef OpenSSLHelper_h
#define OpenSSLHelper_h

#import <Foundation/Foundation.h>

@interface RSAKeyMPIMaterial: NSObject

@property(nonatomic, strong, nonnull) NSString *nDecString;
@property(nonatomic, strong, nonnull) NSString *eDecString;
@property(nonatomic, strong, nonnull) NSString *dDecString;
@property(nonatomic, strong, nonnull) NSString *qDecString;
@property(nonatomic, strong, nonnull) NSString *pDecString;
@property(nonatomic, strong, nonnull) NSString *dmp1DecString;
@property(nonatomic, strong, nonnull) NSString *dmq1DecString;
@property(nonatomic, strong, nonnull) NSString *iqmpDecString;

@end

@interface OpenSSLHelper: NSObject

+ (nonnull RSAKeyMPIMaterial *)generateKeyMPI:(const int)bits exponent:(const unsigned int)exponent;

@end


#endif /* OpenSSLHelper_h */
