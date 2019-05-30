# DMSOpenPGP

<!--[![CI Status](https://img.shields.io/travis/MainasuK<!--/DMSOpenPGP.svg?style=flat)](https://travis-ci.org/MainasuK/DMSOpenPGP)-->
[![Version](https://img.shields.io/cocoapods/v/DMSOpenPGP.svg?style=flat)](https://cocoapods.org/pods/DMSOpenPGP)
[![License](https://img.shields.io/cocoapods/l/DMSOpenPGP.svg?style=flat)](https://cocoapods.org/pods/DMSOpenPGP)
[![Platform](https://img.shields.io/cocoapods/p/DMSOpenPGP.svg?style=flat)](https://cocoapods.org/pods/DMSOpenPGP)

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.

<!--## Requirements-->

## Installation

DMSOpenPGP is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'DMSOpenPGP'
```

## Usage

### Setup

```swift
import BouncyCastle_ObjC

func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {

    // Add provider before use DMSOpenPGP (also add to extension if have)
    JavaSecuritySecurity.addProvider(with: BCJceProviderBouncyCastleProvider())

    return true
}
```

### Keygen
```swift
do {
    let generateKeyData = GenerateKeyData(name: "Hello", email: "alice@alice.pgp", password: "Alice",
                                          masterKey: KeyData(), subkey: KeyData())
    let alice = try DMSPGPKeyRingFactory(generateKeyData: generateKeyData).keyRing
    let armoredPublicKey = alice.publicKeyRing.armored()
    let armoredSecretKey = alice.secretKeyRing.armored()
} catch {
    …
}
```

### Encrypt & Sign
```swift
// encrypt
guard let secretKeyRing = alice.secretKeyRing else {
    return
}

do {
    // with signature
    let encryptor = try DMSPGPEncryptor(publicKeyRings: [alice.publicKeyRing, bob.publicKeyRing, eve.publicKeyRing],
                                        secretKeyRing: secretKeyRing,
                                        password: "Alice")
    let encryptedWithSignatureMessage = try encryptor.encrypt(message: "Message")
    
    // without signature
    let encryptor2 = try DMSPGPEncryptor(publicKeyRings: [alice.publicKeyRing, bob.publicKeyRing, eve.publicKeyRing])
    let encryptedWithoutSignatureMessage = try encryptr2.encrypt(message: "Message")

} catch {
   …
}
```

```swift
// Sign
guard let secretKeyRing = alice.secretKeyRing else {
    return
}

do {
    let encryptor = try DMSPGPEncryptor(secretKeyRing: secretKeyRing, password: "Alice")
    let cleartext = try encryptor.encrypt(message: "Message")
    // or
    let signer = try  DMSPGPSigner(secretKeyRing: keyRing.secretKeyRing, password: password)
    let cleartext2 = signer.sign(message: "Message")
} catch {
    …
}
```

### Decrypt & Verify
```swift
do {
    let decryptor = try DMSPGPDecryptor(armoredMessage: encryptedMessage)
    // decryptor.encryptingKeyIDs contains all decryptable secret keys' keyID   
    let decryptKey = decryptor.encryptingKeyIDs.compactMap { keyID in
        return alice.secretKeyRing?.getDecryptingSecretKey(keyID: keyID)
    }.first
    
    guard let secretKey = decryptKey else { 
        return
    }

    let message = try decryptor.decrypt(secretKey: secretKey, password: "Alice")
    let signatureVerifier = DMSPGPSignatureVerifier(message: message, onePassSignatureList: decryptor.onePassSignatureList, signatureList: decryptor.signatureList)
    let verifyResult = signatureVerifier.verifySignature(use: alice.publicKeyRing)
}
```

Please check DMSOpenPGP/Tests/DMSOpenPGPTests.swift in Example Pods unit tests to see more details.


## Dependencies
- [BouncyCastle-ObjC](https://github.com/DimensionDev/BouncyCastle-ObjC)

## License

DMSOpenPGP is available under the AGPL license. See the LICENSE file for more info.
