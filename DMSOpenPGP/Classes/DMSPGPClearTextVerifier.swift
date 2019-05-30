//
//  DMSPGPClearTextVerifier.swift
//  TesserCube
//
//  Created by Cirno MainasuK on 2019-4-23.
//  Copyright © 2019 Sujitech. All rights reserved.
//

import Foundation
import BouncyCastle_ObjC

/// - Note: RFC4880 - 7. Cleartext Signature Framework
public class DMSPGPClearTextVerifier {

    public let cleartext: String
    public let signature: String

    public let hashHeaders: [String]
    public let message: String
    public let signatureList: BCOpenpgpPGPSignatureList?

    public init(cleartext: String) throws {
        self.cleartext = cleartext

        let scanner = Scanner(string: cleartext)
        scanner.charactersToBeSkipped = nil

        // Jump to cleartext signature begin
        scanner.scanUpTo("-----BEGIN PGP SIGNED MESSAGE-----", into: nil)

        // Read -----BEGIN PGP SIGNED MESSAGE-----\r\n
        var signedMessageHeader: NSString?
        scanner.scanUpToCharacters(from: .newlines, into: &signedMessageHeader)
        scanner.scanCharacters(from: .newlines, into: nil)
        guard signedMessageHeader == "-----BEGIN PGP SIGNED MESSAGE-----" else {
            throw DMSPGPError.invalidCleartext
        }

        // Read armor headers
        var hashHeaders: [String] = []
        var nextLine: NSString? = ""
        var lastScanLocation: Int

        repeat {
            lastScanLocation = scanner.scanLocation
            scanner.scanUpToCharacters(from: .newlines, into: &nextLine)
            scanner.scanString("\r", into: nil)
            scanner.scanString("\n", into: nil)
            guard let hashHeader = nextLine else {
                throw DMSPGPError.invalidCleartext
            }
            nextLine = nil
            hashHeaders.append(hashHeader as String)

            if !scanner.scanUpToCharacters(from: .newlines, into: &nextLine) {
                // got one empty line
                // no more hash header
                break
            }

            if lastScanLocation == scanner.scanLocation {
                // scanner not move
                throw DMSPGPError.invalidCleartext
            }
        } while lastScanLocation != scanner.scanLocation
        self.hashHeaders = hashHeaders

        // Read one empty line
        scanner.scanString("\r", into: nil)
        scanner.scanString("\n", into: nil)

        // Read cleartext
        var rawMessage: NSString?
        scanner.scanUpTo("-----BEGIN PGP SIGNATURE-----", into: &rawMessage)
        let message = rawMessage as String?     // Message could be empty
        self.message = message?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""

        // Read footer
        var footer: NSString?
        scanner.scanUpTo("-----END PGP SIGNATURE-----", into: &footer)

        guard var signature = (footer as String?), !signature.isEmpty else {
            throw DMSPGPError.invalidCleartext
        }
        signature.append(contentsOf: "-----END PGP SIGNATURE-----")
        self.signature = signature

        self.signatureList = try? DMSPGPClearTextVerifier.signatureList(from: signature)
    }

}

extension DMSPGPClearTextVerifier {

    public var signatureVerifier: DMSPGPSignatureVerifier {
        return DMSPGPSignatureVerifier(message: message, onePassSignatureList: nil, signatureList: signatureList)
    }

}

extension DMSPGPClearTextVerifier {

    /// Parse armored PGP Signature
    ///
    /// - Parameter signature: armored PGP signature
    /// - Returns: SignatureList for signature. Return nil when no valid signatureList
    /// - Throws: when invalid input
    public static func signatureList(from signature: String) throws -> BCOpenpgpPGPSignatureList? {
        guard let byteArray = IOSByteArray(nsData: Data(signature.utf8)) else {
            throw DMSPGPError.internal
        }
        let input = JavaIoByteArrayInputStream(byteArray: byteArray)
        guard let armoredInput = BCOpenpgpPGPUtil.getDecoderStream(with: input) as? BCBcpgArmoredInputStream else {
            throw DMSPGPError.notArmoredInput
        }

        do {
            let result = try ExceptionCatcher.catchException {
                let objectFactory = BCOpenpgpPGPObjectFactory(javaIoInputStream: armoredInput, with: BCOpenpgpOperatorJcajceJcaKeyFingerprintCalculator())
                var object = objectFactory.nextObject()

                while object != nil {
                    guard let list = object as? BCOpenpgpPGPSignatureList else {
                        object = objectFactory.nextObject()
                        continue
                    }

                    return list
                }

                return nil
            }

            guard let signatureList = result as? BCOpenpgpPGPSignatureList else {
                return nil
            }

            return signatureList
        } catch {
            return nil
        }
    }

    /// Verify cleartext message
    ///
    /// - Parameter message: armored message
    /// - Returns: true when valid cleartext
    public static func verify(armoredMessage message: String) -> Bool {
        guard let byteArray = IOSByteArray(nsData: Data(message.utf8)) else {
            return false
        }

        let input = JavaIoByteArrayInputStream(byteArray: byteArray)
        guard let armoredInput = BCOpenpgpPGPUtil.getDecoderStream(with: input) as? BCBcpgArmoredInputStream else {
            return false
        }

        return armoredInput.isClearText()
    }

}
