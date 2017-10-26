open class OktaJWTSigner: NSObject {
    private var payload: JSONWebToken.Payload
    private var signingType: OktaJWTSigningType
    private var key: RSAKey?
    
    /**
     Default constructor for the OktaJWTSigner class.
     - parameters:
         - options: Set of key, value pairs as the JWT claim set
     */
    
    public init(_ payload: [String: Any]) {
        self.init(payload, leeway: 3000)
    }
    
    public init(_ payload: [String: Any], leeway: Int) {
        var mPayload = JSONWebToken.Payload()
        let now = Date()
        
        if payload["iss"] != nil {
            mPayload.issuer = Utils.removeTrailingSlash(payload["iss"] as! String)
        }
        
        if payload["aud"] != nil {
            mPayload.audience = [Utils.removeTrailingSlash(payload["aud"] as! String)]
        }
        
        if payload["exp"] == nil {
            mPayload.expiration = now
        }
        
        if payload["iat"] == nil {
            mPayload.issuedAt = now.addingTimeInterval(Double(leeway))
        }
        
        if payload["nbf"] == nil {
            mPayload.notBefore = now.addingTimeInterval(Double(leeway) * -1)
        }
        
        self.payload = mPayload
        self.signingType = .RSA
    }
}

