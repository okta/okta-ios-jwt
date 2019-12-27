//
//  RSASSA_PKCS1.swift
//  JSONWebToken
//
//  Created by Antoine Palazzolo on 18/11/15.
//

import Foundation
import Security

internal func paddingForHashFunction(_ f : SignatureAlgorithm.HashFunction) -> SecPadding {
    switch f {
    case .sha256:
        return SecPadding.PKCS1SHA256
    case .sha384:
        return SecPadding.PKCS1SHA384
    case .sha512:
        return SecPadding.PKCS1SHA512
    }
}



public struct RSAKey {
    enum Error : Swift.Error {
        case securityError(OSStatus)
        case publicKeyNotFoundInCertificate
        case cannotCreateCertificateFromData
        case invalidP12ImportResult
        case invalidP12NoIdentityFound
    }
    let value : SecKey
        
    public init(secKey :SecKey) {
        self.value = secKey
    }
    public init(secCertificate cert: SecCertificate) throws {
        var trust : SecTrust? = nil
        let result = SecTrustCreateWithCertificates(cert, nil, &trust)
        if result == errSecSuccess && trust != nil {
            if let publicKey = SecTrustCopyPublicKey(trust!) {
                self.init(secKey : publicKey)
            } else {
                throw Error.publicKeyNotFoundInCertificate
            }
        } else {
            throw Error.securityError(result)
        }
    }
    //Creates a certificate object from a DER representation of a certificate.
    public init(certificateData data: Data) throws {
        if let cert = SecCertificateCreateWithData(nil, data as CFData) {
            try self.init(secCertificate : cert)
        } else {
            throw Error.cannotCreateCertificateFromData
        }
    }
    
    public static func keysFromPkcs12Identity(_ p12Data : Data, passphrase : String) throws -> (publicKey : RSAKey, privateKey : RSAKey) {
        
        var importResult : CFArray? = nil
        let importParam = [kSecImportExportPassphrase as String: passphrase]
        let status = SecPKCS12Import(p12Data as CFData,importParam as CFDictionary, &importResult)
        
        guard status == errSecSuccess else { throw Error.securityError(status) }
        
        if let array = importResult.map({unsafeBitCast($0,to: NSArray.self)}),
            let content = array.firstObject as? NSDictionary,
            let identity = (content[kSecImportItemIdentity as String] as! SecIdentity?)
        {
            var privateKey : SecKey? = nil
            var certificate : SecCertificate? = nil
            let status = (
                SecIdentityCopyPrivateKey(identity, &privateKey),
                SecIdentityCopyCertificate(identity, &certificate)
            )
            guard status.0 == errSecSuccess else { throw Error.securityError(status.0) }
            guard status.1 == errSecSuccess else { throw Error.securityError(status.1) }
            if privateKey != nil && certificate != nil {
                return try (RSAKey(secCertificate: certificate!),RSAKey(secKey: privateKey!))
            } else {
                throw Error.invalidP12ImportResult
            }
        } else {
            throw Error.invalidP12NoIdentityFound
        }
    }
}
