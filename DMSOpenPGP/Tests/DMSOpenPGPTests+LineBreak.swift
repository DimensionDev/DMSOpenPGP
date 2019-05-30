//
//  DMSOpenPGPTests+LineBreak.swift
//  TesserCubeTests
//
//  Created by Cirno MainasuK on 2019-5-10.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import XCTest
import BouncyCastle_ObjC
import DMSOpenPGP

class DMSOpenPGPTests_LineBreak: XCTestCase {

    override class func setUp() {
        JavaSecuritySecurity.addProvider(with: OrgBouncycastleJceProviderBouncyCastleProvider())
    }

    func testTestLineBreak() {
        let decryptor = try! DMSPGPDecryptor(armoredMessage: armoredMessage)
        let keyID = decryptor.encryptingKeyIDs.first { DMSOpenPGPTests.RSA.secretKeyRing!.getDecryptingKeyIDs().contains($0) }
        let secretKey = DMSOpenPGPTests.RSA.secretKeyRing?.getDecryptingSecretKey(keyID: keyID!)
        let message = try! decryptor.decrypt(secretKey: secretKey!, password: "RSA")
        XCTAssertEqual(message, "test 101")
    }

    func testTestLineBreak2() {
        let decryptor = try! DMSPGPDecryptor(armoredMessage: armoredMessage2)
        let keyID = decryptor.encryptingKeyIDs.first { DMSOpenPGPTests.RSA.secretKeyRing!.getDecryptingKeyIDs().contains($0) }
        let secretKey = DMSOpenPGPTests.RSA.secretKeyRing?.getDecryptingSecretKey(keyID: keyID!)
        let message = try! decryptor.decrypt(secretKey: secretKey!, password: "RSA")
        XCTAssertEqual(message, "test 101")
    }

}

private let armoredMessage = """
-----BEGIN PGP MESSAGE-----

hQIMAzihUfFi+P/2ARAAmYrFYSD7OP+Opwh2n4plHazSGKqzdmgY20cIyONL7RiA
cMtex6zfeYI71lilY6OvmIdUtjoPCD/h4XuSkCURQNEdBGxHPmaQwl+q0nglNyO9
TrW03Y7pCob5IxNyccQ46zlEgwJyu+S4fPt57fnyqu/03rrJhtTfUJNs6Cf3wDjg
Qu5/Q+XrO4vR0QN9HyfhAmQIRN/cYZR5yGkTGVCPmsN8jwCJAOprItZ/pCO4/FpY
sH92Y2ZvQK6GXAVnRysXie+cwcwzi/SuUyvEoycM1JuY6FQiORnXbxuztiJCU1Af
g1W+G2kzO9mwhlZF7zAm/ZTuOnZe478by7X93nHeHK3GbO3f7fAewINOkg/uLmuE
KeVrAMoKfeoEAOETnVcr/t+BbGX9+6aAMBM0mz41CDnvUvqO2WmpX2Vzuh/mzNDO
/Ph087kYklpIdFZ1xi1T4Rxli5rAYN2ZSimS0u7tI/pTpNQa9FQtTrRpmDZ+sc5L
rPeIr4tfQpy7qVZYKIJv3InI3fmkvmmjr93DMAUbmPVGHZO+slZR5dpuBGKlnuoH
P9vssZUFZjpsTopOz9o+xtAKdLqz6ymdvBTtRqOh+Sp2G7MK/uTlUg6t2iNX3sGc
qhTMjzy2xD+AQabjBccSkJ4EBXDa4Hx6Ul7BgQZgQw2M00KV1RJwUx9I9cyKNd/S
6QFLizftADoemYMS9JsjWUhBUQZnxRgMZqy/ze7IJgkWrdyCVCo4jW8X+uUjNC8b
RWK1TFydG29czyo2yRm/e5CVOoHlkVPT8bU1CpA354go09QFvdAWOuv+s0V4Timl
scRBWibpIPResZK+PuPamPo9iJL2NiO4HvcBGkwVIoaPSFUjTp78ak6Ztmkd28k8
NrmS75Uefzrknhm4h0FhrBAB65WwPyVeN0xRIKdqsktTubLxLVYAuo1UydsOrFVG
VtR2kgoigxCbqjM4dnRMpxXo33hTxO3TNC8Skj77OCO7rrXN+rwBSa420bxLH2Yv
AW4OaqzdLKRRrdEVTrFoC9LCWZdqkr+PRdEh5LOhZ3l4MGXjNLlxaJqcnWANSb77
E+/viyauN60ozQlFtjXjYsLxZ8tbWsg2GAAfL9NGtoSvOGeug0AMaE99gkPKJjUX
ms8rWPECpRcWt2Y8sMHLMhJCWTgRQTiXjRd+4xHSG3VyIW83LO8dsAoTm28GvpZz
VI0hM8W32Y9WoTm/zBsUYkMcJdRgUTcd7eiJJEdIc0S9kWPq9bqxeCMzukG+nO5z
0s15uTwq2m48wIdEp4zWvCMtcaKdnoP/f0LqqTFOt9jr6Y+0wpMV3FyGWOXk+pfk
LblESaTfX3tTNrgbvRa/r8F3Dl9Nw49zl+5lbbW7RVG5jPVio7T6GlNHs8TohEUS
fLr89Dqmx7fcliKZBPOHEWo321k6z2SN1hU8ec/3+gbOceP7uIdSYdsccHUoa5Bs
1XDelDkuZ4eTzH5mW05Z2NCgSqHxEoqPM3JNBMpin1lNzvGlt3HRva+qz0vRWsUf
2+gFEmmKZ2kht8DIvnFEgHW/ADWiERS+UuZYMWZo
=efYM
-----END PGP MESSAGE-----
"""

private let armoredMessage2 = """
-----BEGIN PGP MESSAGE-----

hQIMAzihUfFi+P/2AQ/+L+AV9UmRC4NXNbkXTQ3ZJ9znw8VNWSD0iwfXugNcGd2D
8WknBcCuq8gjxOizCjun7h/oGMy09ZG2I3aL1a+nm3+tOaFltvPFBXwNJsAJFPb4
Cpx2HF2qL0LGs8gk7So2J6+mUTjWAlJZg8ZgVQ9fC729ppJOe1FzSTiUjs+A1tsM
2fOO+sRgGop9xwfvEI30Nyk67g73/Hesk+vb0qiu329f3l7ZW8vYRhnvVbHaeFc8
D4L654O0aF1w6OYXA7UjRraxCXdzhuu48bQ3MZiKyi1Ybrq3WSwV0xE6oiJTpola
m/DOgrnMJw/BK2FlR7KvrlEb0zASUYvwzFzcyn/bPDeUrv5Ci9qxyFhvylE5P5es
AYeHNGoyvg79p1zdgNo12ZWGzyuYbxBITEA7S2DSGUTwRsKGExb66HniM+0xRfXQ
kTa37KatTbMb/RjGxdTrAJEWyxDIDsvZSYM78V5UpS0JFXcNRGPNovwJzezqTXTu
YUaMk1cm2vFH1vePiaeF7N0Ll1oRF09g0GJdpTAYiDpJVjVfUsEPYrKVyfpfMWmb
Z6vC9rSNMMj/Kn6wltdAfoQdiqybnX8lyRJ0Ykm/WT/btY+j9PStmPd6gXdQrZaZ
3XqkhJUH7RNlPb/Gl3gcJCDMDGLnolPLRvf9TfUOPSmu+89fu/rut9tMXh/oP//S
6QFP1p57xEF20Cp09GX2VfREWFNu5weY6gDc1Q23Vap1VwGpfYSWyLWMMMIkodpX
i7YSSbyg/bJ3dxa1PPV0DZ7eGJO0imWKXgq6M8d8iEYJQV0VnHHR3GS4iU6pEAsO
qinBrMyNbXPe/aoKrFfhjw9B3l7VKI8F3UURZnItWW7eSE7a04RZ6jVSEIJVQNew
zXpkiFS464EFZ47eXpLVcsIGkmBe6Q6/TA90FIoyqO4C7y6WXGF7GOyd2EA+O0uO
7t9O2cUmlr0aQkzSLreeDK8HvbnhHTRBXD6xsFi+AXjdmX1pjfhW7BGXftOXg97n
9L1L/k6bjb1dwCkPjXJX237s+N/dkxqqsenoS6chiZaadzw0FvG22NgC30NWCoE+
fW8F/7Vm9AdIAJjh7CiB0vSJ7am+c+pZAnnhy0E8Fe/Q9u8G2n/Fp5j1yIOlFlfh
Gf+ZKMXy6WbfNqmPvsVeJyf6pdk6GtSbKqYPtsBAt/vjm4RwM97G2nrQreIsbH8U
Feb5lIHoa/Cmiz3WEAoWhx3h+uX2TvjGhZ8hehdvwwBxHotZCWhG5ESh4sUI1ADE
zRVTjAbOMkQwAZPdjiiqMUgBVrsAxbRw6qz8J1oqjsswzcOAoU2iKRamaDamUmAx
vczo/r7Y/kFYWw0KByKBQkrmrpBklPqI9d8lpNszFVofjWdOJwVOqh/4zF75Y4AN
dEbBSDk5hIMV0/RBmaaNQHH2OLpWnNANm6xI6R3XYRgVCZCCdkEgQR6CBFi4lgt9
uED7C70I0/XKbo9PsrzweZt4gG2sXC9FSqFvHmIhtCHwOvXFElJ7dyQ3NM0MU1v9
WD/Ezc8xAKvCh6eXn69SC2QgJM3eD1O46HxM0to2bA==
=aSLQ
-----END PGP MESSAGE-----
"""
