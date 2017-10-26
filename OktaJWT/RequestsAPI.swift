open class RequestsAPI: NSObject {
    
    /**
     Returns the OpenID Connect well-known metadata.
     - parameters:
         - issuer: String of the issuer of the JWT
     - returns:
     The JSON response from the URL
     */
    open class func getDiscoveryDocument(issuer: String) -> [String: Any]? {
        // Extracts the discovery information from the OpenID Connect metadata object
        let discoveryUrl = URL(string: issuer + "/.well-known/openid-configuration")
        guard let data = self.get(discoveryUrl!) else {
            return nil
        }
        
        if let response = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
            let json = response {
            return json
        }
        
        return nil
    }
    
    /**
     Extracts the JSON Web Keys URL information from the OpenID Connect metadata object.
     - parameters:
         - json: The JSON response from the OpenID Connect well-known endpoint
     - returns:
     The "jwks_uri" URL as a String
     */
    open class func getKeysEndpoint(json: [String: Any]) -> String? {
        if let keysEndpoint = json["jwks_uri"] {
            return keysEndpoint as? String
        }
        
        return nil
    }
    
    /**
     Extracts the issuer URL from the OpenID Connect metadata object.
     - parameters:
         - issuer: The "valid" issuer in which to call the well-known endpoint
     - returns:
     The "issuer" URL as a String
     */
    open class func getIssuerEndpoint(issuer: String) -> String? {
        if let json = getDiscoveryDocument(issuer: issuer), let issuerEndpoint = json["issuer"] {
            return issuerEndpoint as? String
        }
        
        return nil
    }
    
    /**
     Returns the GET HTTP response as a JSON object.
     - parameters:
         - url: URL to fetch
     - returns:
     A JSON representation of the HTTP response body.
     */
    open class func getJSON(_ url: URL) -> [String: Any]? {
        let data = self.get(url)
        
        if let json = try? JSONSerialization.jsonObject(with: data!, options: []) as? [String: Any] {
            return json
        }
        
        return nil
    }
    
    /**
     Returns the GET HTTP response as the raw Data object.
     - parameters:
         - url: URL to fetch
     - returns:
     A Data representation of the HTTP response body.
     */
    open class func get(_ url: URL) -> Data? {
        // Default timeout of 5 seconds
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 5)
        request.addValue("okta-ios-jwt/\(VERSION) iOS/]\(UIDevice.current.systemVersion)", forHTTPHeaderField: "X-Okta-Agent")
        
        do {
            let response: AutoreleasingUnsafeMutablePointer<URLResponse?>? = nil
            return try? NSURLConnection.sendSynchronousRequest(request, returning: response)
        }
    }
}
