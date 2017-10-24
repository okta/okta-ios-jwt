/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

let VERSION = "0.1.0"

public struct OktaJWTValidator {
    private var validatorOptions: [String: Any]
    private var validationType: OktaJWTValidationType
    private var jwk: [String: String]?
    private var key: RSAKey?
    private var wellKnown: [String: Any]?

    /**
         Default constructor for the OktaJWTValidator class.
         - parameters:
             - options: Set of key, value pairs to validate the JWK against
     */
    public init(_ options: [String: Any]) {
        var mOptions = options
        if mOptions["issuer"] != nil {
            // Update issuer to "iss"
            mOptions["iss"] = Utils.removeTrailingSlash(mOptions["issuer"] as! String)
            mOptions.removeValue(forKey: "issuer")
        }

        if mOptions["audience"] != nil {
            // Update audience to "aud"
            mOptions["aud"] = Utils.removeTrailingSlash(mOptions["audience"] as! String)
            mOptions.removeValue(forKey: "audience")
        }

        if mOptions["exp"] == nil {
            // Ensure the exp value is checked
            mOptions["exp"] = true
        }

        if mOptions["iat"] == nil {
            // Ensure the iat value is checked
            mOptions["iat"] = true
        }

        self.validatorOptions = mOptions
        self.validationType = OktaJWTValidationType.JWK
    }

    /**
         Constructor for the OktaJWTValidator class.
         - parameters:
             - options: Set of key, value pairs to validate the JWK against
             - jwk: JSON Web Key to validate the token against
     */
    public init(_ options: [String: Any], jwk: [String: String]) {
        self.init(options)
        self.validationType = OktaJWTValidationType.JWK
        self.jwk = jwk
    }

    /**
         Constructor for the OktaJWTValidator class.
         - parameters:
             - options: Set of key, value pairs to validate the JWK against
             - key: RSAKey to validate the token against
     */
    public init(_ options: [String: Any], key: RSAKey) {
        self.init(options)
        self.validationType = OktaJWTValidationType.RSAKey
        self.key = key
    }

    /**
         Validates if the JSON Web Token meets the set of criteria set in the constructor.
         - parameters:
             - rawJWT: String representation of the JWT
     */
    public func isValid(_ rawJWT: String) throws -> Bool {
        var jwt: JSONWebToken

        do {
            jwt = try JSONWebToken(string: rawJWT)
        }
        catch {
            throw OktaError.jwtError("String injected is not formatted as a JSON Web Token")
        }

        // Check for valid algorithm type
        if !Utils.isSupportedAlg(jwt.signatureAlgorithm.jwtIdentifier) {
            throw OktaError.jwtError("The JWT algorithm \(jwt.signatureAlgorithm.jwtIdentifier) is not supported at this time.")
        }

        // Check for valid issuer - REQUIRED
        if !OktaJWTValidation.hasValidIssuer(jwt.payload.issuer, validIssuer: self.validatorOptions["iss"] as? String) {
            throw OktaError.jwtError("Token issuer: \(String(describing: jwt.payload.issuer!)) does not match the valid issuer")
        }

        // Check for valid audience - REQUIRED
        if !OktaJWTValidation.hasValidAudience(jwt.payload.audience, validAudience: self.validatorOptions["aud"] as? String) {
            throw OktaError.jwtError("Token audience: \(String(describing: jwt.payload.audience)) does not match the valid audience")
        }

        // TODO Support azp claim

        guard let kid = Utils.getKeyIdFromHeader(jwt.decodedDataForPart(.header)) else {
            throw OktaError.jwtError("Could not retrieve kid from JWT")
        }

        // Validate the JWK signature
        var key: RSAKey
        switch self.validationType {
            case .JWK:
                if let givenJWK = self.jwk, let givenJWKId = givenJWK["kid"] {
                    key = try self.getOrRetrieveKey(jwk: givenJWK, kid:givenJWKId)
                }
                key = try self.getOrRetrieveKey(jwk: nil, kid: kid)
            case .RSAKey:
                key = self.key!
        }

        let signatureValidation = RSAPKCS1Verifier(key: key, hashFunction: .sha256).validateToken(jwt)
        if !signatureValidation.isValid {
            throw OktaError.jwtError("Signature validation failed")
        }

        // Validate the exp claim with or without leeway
        if let validateExp = self.validatorOptions["exp"] as? Bool, validateExp == true {
            if OktaJWTValidation.isExpired(jwt.payload.expiration, leeway: self.validatorOptions["leeway"] as? Int) {
                throw OktaError.jwtError("The JWT expired and is no longer valid")
            }
        }

        // Validate the iat claim with or without leeway
        if let validateIssuedAt = self.validatorOptions["iat"] as? Bool, validateIssuedAt == true {
            if OktaJWTValidation.isIssuedInFuture(jwt.payload.issuedAt, leeway: self.validatorOptions["leeway"] as? Int) {
                throw OktaError.jwtError("The JWT was issued in the future")
            }
        }

        // Validate the nonce claim
        if let nonce = jwt.payload.jsonPayload["nonce"] as? String {
            if !OktaJWTValidation.hasValidNonce(nonce, validNonce: self.validatorOptions["nonce"] as? String) {
                throw OktaError.jwtError("Invalid JWT nonce")
            }
        }

        // Misc Validation
        let testedValues = ["iss", "aud", "exp", "iat", "iss", "leeway", "nonce"] as [String]
        for (k, v) in self.validatorOptions {
            if testedValues.contains(k) {
                continue
            }
            if !OktaJWTValidation.hasValue(jwt.payload.jsonPayload[k] as? String, validClaim: v as? String) {
                throw OktaError.jwtError("JWT does not contain \"\(v)\" in the payload")
            }

        }

        return true
    }

    /**
         Returns the stored RSAKey matching the kid or creates one.
         - parameters:
             - jwk: The JSON Web Key deserialzed into key, value pairs
             - kid: String of the extracted kid from the token's header
         - returns:
         An RSAKey for validating the JWKs signature
     */
    private func getOrRetrieveKey(jwk: [String: String]?, kid: String) throws -> RSAKey {
        if let key = RSAKey.registeredKeyWithTag("com.okta.jwt.\(kid)") {
            return key
        }

        var mJWK: [String: String]

        if jwk == nil {
            // Set the class's wellKnown object to ensure we validate the JWT based on values pulled from the well-known endpoint
            guard let wellKnown = OktaAPI.getDiscoveryDocument(issuer: validatorOptions["iss"] as! String) else {
                throw OktaError.apiError("Could not retrieve well-known metadata endpoint")
            }

            // Call keys endpoint and find matching kid and create key
            guard let keysEndpoint = OktaAPI.getKeysEndpoint(json: wellKnown) else {
                throw OktaError.apiError("Unable to capture jwks_uri from well-known endpoint")
            }

            guard let mKey = Utils.getKeyFromEndpoint(kid: kid, keysEndpoint) else {
                throw OktaError.jwtError("Could not retrieve JWK")
            }
            mJWK = mKey
        } else {
            mJWK = jwk!
        }
        return try self.createRSAKey(mJWK, kid: kid)
    }

    /**
         Creates a new RSAKey given a JWK.
         - parameters:
             - jwk: The JSON Web Key deserialzed into key, value pairs
             - kid: String of the extracted kid from the token's header
         - returns:
         An RSAKey for validating the JWKs signature
     */
    private func createRSAKey(_ jwk: [String: String], kid: String) throws -> RSAKey {
        let decodedModulus = Utils.base64URLDecode(jwk["n"])
        let decodedExponent = Utils.base64URLDecode(jwk["e"])

        if decodedModulus == nil || decodedExponent == nil {
            throw OktaError.jwtError("Modulus or exponent from JWK could not be parsed")
        }

        let key = try RSAKey.registerOrUpdateKey(modulus: decodedModulus!, exponent: decodedExponent!, tag: "com.okta.jwt.\(kid)")

        // Cache key
        OktaKeychain.loadKey(tag: "com.okta.jwt.\(kid)")

        return key
    }
}
