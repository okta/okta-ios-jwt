public struct OktaJWTSigner {
    private var payload: JSONWebToken.Payload
    private var signingType: OktaJWTSigningType
    private var key: RSAKey

    /**
     Default constructor for the OktaJWTSigner class.
     - parameters:
         - payload: Set of key, value pairs to sign
         - signType: Method to sign the payload
         - key: Private key for signing the JWT
     */
    public init(_ payload: [String: Any], signType: OktaJWTSigningType, key: RSAKey) {
        var mOptions = payload

        if payload["iss"] != nil {
            mOptions["iss"] = Utils.removeTrailingSlash(payload["iss"] as! String)
        }

        if payload["aud"] != nil {
            if payload["aud"] is String {
                mOptions["aud"] = [Utils.removeTrailingSlash(payload["aud"] as! String)]
            }
            else if payload["aud"] is [String], let audArray = payload["aud"] as? [String] {
                var formattedAud = [String]()
                for aud in audArray {
                    formattedAud.append(Utils.removeTrailingSlash(aud))
                }
                mOptions["aud"] = formattedAud
            } else {
                mOptions["aud"] = nil
            }
        }

        if payload["exp"] != nil, let date = payload["exp"] as? Date {
            mOptions["exp"] = round(date.timeIntervalSince1970)
        }

        if payload["iat"] != nil, let date = payload["iat"] as? Date {
            mOptions["iat"] = round(date.timeIntervalSince1970)
        }
        
        if payload["nbf"] != nil, let date = payload["nbf"] as? Date {
            mOptions["nbf"] = round(date.timeIntervalSince1970)
        }

        self.payload = JSONWebToken.Payload()
        self.payload.jsonPayload = mOptions
        self.signingType = signType
        self.key = key
    }

    /**
     Generate the JWT as a string.
     - returns: JWT as a raw string
     */
    public func jwt() throws -> String {
        var mJWT: JSONWebToken

        switch self.signingType {
            case .RSA:
                let signer = RSAPKCS1Signer(hashFunction: .sha256, key: self.key)
                do {
                    mJWT = try JSONWebToken(payload: self.payload, signer: signer)
                } catch {
                    throw OktaJWTSigningError.SigningError(error.localizedDescription)
                }
            default:
                throw OktaJWTSigningError.SigningError(self.signingType.rawValue)
        }
        return mJWT.rawString
    }
}
