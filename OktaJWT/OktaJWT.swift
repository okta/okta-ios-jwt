let VERSION = "0.1.0"

public struct OktaJWTValidator {
    private var validatorOptions: [String: Any]
    private var validationType: OktaJWTVerificationType
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
        self.validationType = OktaJWTVerificationType.JWK
    }
    
    /**
     Constructor for the OktaJWTValidator class.
     - parameters:
         - options: Set of key, value pairs to validate the JWK against
         - jwk: JSON Web Key to validate the token against
     */
    public init(_ options: [String: Any], jwk: [String: String]) {
        self.init(options)
        self.validationType = OktaJWTVerificationType.JWK
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
        self.validationType = OktaJWTVerificationType.RSAKey
        self.key = key
    }
    
    /**
     Validates if the JSON Web Token meets the set of criteria set in the constructor.
     - parameters:
         - rawJWT: String representation of the JWT
     - returns:
     True is the token is valid or throws an error
     */
    public func isValid(_ rawJWT: String) throws -> Bool {
        var jwt: JSONWebToken
        
        do {
            jwt = try JSONWebToken(string: rawJWT)
        }
        catch {
            throw OktaJWTVerificationError.MalformedJWT
        }
        
        // Check for valid algorithm type
        if !Utils.isSupportedAlg(jwt.signatureAlgorithm.jwtIdentifier) {
            throw OktaJWTVerificationError.NonSupportedAlg(jwt.signatureAlgorithm.jwtIdentifier)
        }
        
        // Check for valid issuer - REQUIRED
        if !OktaJWTVerifier.hasValidIssuer(jwt.payload.issuer, validIssuer: self.validatorOptions["iss"] as? String) {
            throw OktaJWTVerificationError.InvalidIssuer
        }
        
        // Check for valid audience - REQUIRED
        if !OktaJWTVerifier.hasValidAudience(jwt.payload.audience, validAudience: self.validatorOptions["aud"] as? String) {
            throw OktaJWTVerificationError.InvalidAudience
        }
        
        // TODO Support azp claim
        
        guard let kid = Utils.getKeyIdFromHeader(jwt.decodedDataForPart(.header)) else {
            throw OktaJWTVerificationError.NoKIDFromJWT
        }
        
        // Validate the JWK signature
        var key: RSAKey
        switch self.validationType {
            case .JWK:
                if let givenJWK = self.jwk, let givenJWKId = givenJWK["kid"] {
                    if givenJWKId != kid {
                        throw OktaJWTVerificationError.InvalidKID
                    }
                    key = try self.getOrRetrieveKey(jwk: givenJWK, kid:givenJWKId)
                    break
                }
                key = try self.getOrRetrieveKey(jwk: nil, kid: kid)
            case .RSAKey:
                key = self.key!
        }
        
        let signatureValidation = RSAPKCS1Verifier(key: key, hashFunction: .sha256).validateToken(jwt)
        if !signatureValidation.isValid {
            throw OktaJWTVerificationError.InvalidSignature
        }
        
        // Validate the exp claim with or without leeway
        if let validateExp = self.validatorOptions["exp"] as? Bool, validateExp == true {
            if OktaJWTVerifier.isExpired(jwt.payload.expiration, leeway: self.validatorOptions["leeway"] as? Int) {
                throw OktaJWTVerificationError.ExpiredJWT
            }
        }
        
        // Validate the iat claim with or without leeway
        if let validateIssuedAt = self.validatorOptions["iat"] as? Bool, validateIssuedAt == true {
            if OktaJWTVerifier.isIssuedInFuture(jwt.payload.issuedAt, leeway: self.validatorOptions["leeway"] as? Int) {
                throw OktaJWTVerificationError.IssuedInFuture
            }
        }
        
        // Validate the nonce claim
        if let nonce = jwt.payload.jsonPayload["nonce"] as? String {
            if !OktaJWTVerifier.hasValidNonce(nonce, validNonce: self.validatorOptions["nonce"] as? String) {
                throw OktaJWTVerificationError.InvalidNonce
            }
        }
        
        // Misc Verification
        let testedValues = ["iss", "aud", "exp", "iat", "iss", "leeway", "nonce"] as [String]
        for (k, v) in self.validatorOptions {
            if testedValues.contains(k) {
                continue
            }
            if !OktaJWTVerifier.hasValue(jwt.payload.jsonPayload[k] as? String, validClaim: v as? String) {
                throw OktaJWTVerificationError.InvalidClaim(v)
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
            guard let wellKnown = RequestsAPI.getDiscoveryDocument(issuer: validatorOptions["iss"] as! String) else {
                throw OktaAPIError.NoWellKnown
            }
            
            // Call keys endpoint and find matching kid and create key
            guard let keysEndpoint = RequestsAPI.getKeysEndpoint(json: wellKnown) else {
                throw OktaAPIError.NoJWKSEndpoint
            }
            
            guard let mKey = Utils.getKeyFromEndpoint(kid: kid, keysEndpoint) else {
                throw OktaAPIError.NoKey
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
            throw OktaJWTVerificationError.InvalidModulusOrExponent
        }
        
        let key = try RSAKey.registerOrUpdateKey(modulus: decodedModulus!, exponent: decodedExponent!, tag: "com.okta.jwt.\(kid)")
        
        // Cache key
        OktaKeychain.loadKey(tag: "com.okta.jwt.\(kid)")
        
        return key
    }
}
