//
//  OpenSSLHelper.m
//  TesserCube
//
//  Created by jk234ert on 2019/4/25.
//  Copyright © 2019 Sujitech. All rights reserved.
//

#import <Foundation/Foundation.h>

#import <Security/Security.h>
#import <openssl/err.h>
#import <openssl/ssl.h>

#import <openssl/bn.h>
#import <openssl/rsa.h>

#import "OpenSSLHelper.h"

@implementation RSAKeyMPIMaterial

- (instancetype)initWithRsa:(RSA *)rsa {
    if ((self = [super init])) {
        _nDecString = [[NSString alloc] initWithUTF8String:BN_bn2dec(rsa->n)];
        _eDecString = [[NSString alloc] initWithUTF8String:BN_bn2dec(rsa->e)];
        _dDecString = [[NSString alloc] initWithUTF8String:BN_bn2dec(rsa->d)];
        _pDecString = [[NSString alloc] initWithUTF8String:BN_bn2dec(rsa->p)];
        _qDecString = [[NSString alloc] initWithUTF8String:BN_bn2dec(rsa->q)];
        _dmp1DecString = [[NSString alloc] initWithUTF8String:BN_bn2dec(rsa->dmp1)];
        _dmq1DecString = [[NSString alloc] initWithUTF8String:BN_bn2dec(rsa->dmq1)];
        _iqmpDecString = [[NSString alloc] initWithUTF8String:BN_bn2dec(rsa->iqmp)];
    }
    return self;
}

- (NSData *)dataFromBigNUM:(BIGNUM *)bigNum {
    size_t buflen = (size_t)(BN_num_bytes(bigNum));
    void *buf = calloc(buflen, 1);
    BN_bn2bin(bigNum, buf);
    NSData* result = [NSData dataWithBytes:buf length:buflen];
    if (buf) {
        free(buf);
    }
    return result;
}

@end

@implementation OpenSSLHelper

+ (nonnull RSAKeyMPIMaterial *)generateKeyMPI:(const int)bits exponent:(const unsigned int)exponent {
    BN_CTX *ctx = BN_CTX_new();
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    
    BN_set_word(e, exponent);
    
    if (RSA_generate_key_ex(rsa, bits, e, NULL) != 1) {
        return nil;
    }
    
    RSAKeyMPIMaterial *material = [[RSAKeyMPIMaterial alloc] initWithRsa:rsa];
    
    BN_CTX_free(ctx);
    BN_clear_free(e);
    RSA_free(rsa);
    
    return material;
}

@end
