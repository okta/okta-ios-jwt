open class Utils: NSObject {
    
    /**
     Removes the trailing slash for the supplied issuer param.
     - parameters:
         - issuer: String representation of the issuer URL
     - returns:
     A modified String of the issuer without the trailing '/'
     */
    open class func removeTrailingSlash(_ issuer: String) -> String {
        if let hasTrailingSlash = issuer.characters.last {
            var newIssuer = issuer
            return hasTrailingSlash == "/" ? String(newIssuer.characters.dropLast()) : issuer
        }
        
        return issuer
    }
    
    /**
     Base 64 URL decodes a given String.
     - parameters:
         - input: String representation of the value to be decoded
     - returns:
     The decoded String as a Data object
     */
    open class func base64URLDecode(_ input: String?) -> Data? {
        if input == nil { return nil }
        
        var base64 = input!
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        
        let length = Double(base64.lengthOfBytes(using: .utf8))
        let requiredLength = 4 * ceil(length / 4.0)
        let paddingLength = requiredLength - length
        if paddingLength > 0 {
            let padding = "".padding(toLength: Int(paddingLength), withPad: "=", startingAt: 0)
            base64 = base64 + padding
        }
        
        return Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
    }
    
    /**
     Checks to see if the current "alg" type is supported by this library.
     - parameters:
         - alg: String abbreviation of the algorithm type
     - returns:
     A boolean if the alg type is supported
     */
    open class func isSupportedAlg(_ alg: String) -> Bool {
        switch alg {
            case "RS256":
                return true
            default:
                return false
        }
    }
    
    /**
     Parses the kid from the JWT header.
     - parameters:
         - header: Base64Decoded header object
     - returns:
     String representation of the JWT's kid
     */
    open class func getKeyIdFromHeader(_ header: Data) -> String? {
        let json = try? JSONSerialization.jsonObject(with: header, options: []) as! [String: Any]
        if let kid = json?["kid"] {
            // Return the kid from the header object
            return String(describing: kid)
        }
        
        return nil
    }
    
    /**
     Returns the matching key from the jwks_uri endpoint.
     - parameters:
         - kid: String representation of the kid to find
         - keysEndpoint: String of the endpoint to request the JWKs
     - returns:
     A JSON Web Key dictionary matching the JWTs kid
     */
    open class func getKeyFromEndpoint(kid: String, _ keysEndpoint: String) -> [String: String]? {
        let url = URL(string: keysEndpoint)
        guard let keys = RequestsAPI.getJSON(url!)?["keys"] as? [Any] else {
            return nil
        }
        
        return self.findKeyByKeyId(kid: kid, keys)
    }
    
    /**
     Returns the matching key from a list of objects.
     - parameters:
         - kid: String representation of the kid to find
         - keys: Array of keys to evaluate
     - returns:
     A JSON Web Key dictionary matching the JWTs kid
     */
    open class func findKeyByKeyId(kid: String, _ keys: [Any]) -> [String: String]? {
        for key in keys {
            let keyDict = key as! [String: String]
            guard let dirtyKid = keyDict["kid"] else {
                continue
            }
            if dirtyKid == kid {
                return keyDict
            }
        }
        
        return nil
    }
}
