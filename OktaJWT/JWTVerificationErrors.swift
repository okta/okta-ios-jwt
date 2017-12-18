public enum OktaJWTVerificationError: Error {
    case MalformedJWT
    case NonSupportedAlg(String)
    case InvalidIssuer
    case InvalidAudience
    case NoKIDFromJWT
    case InvalidKID
    case InvalidSignature
    case InvalidModulusOrExponent
    case ExpiredJWT
    case IssuedInFuture
    case InvalidNonce
    case InvalidClaim(Any)
}

extension OktaJWTVerificationError: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .MalformedJWT:
                return NSLocalizedString("String injected is not formatted as a JSON Web Token", comment: "")
            case .NonSupportedAlg(alg: let alg):
                return NSLocalizedString("The JWT algorithm \(alg) is not supported at this time", comment: "")
            case .InvalidIssuer:
                return NSLocalizedString("Token issuer does not match the valid issuer", comment: "")
            case .InvalidAudience:
                return NSLocalizedString("Token audience does not match the valid audience", comment: "")
            case .NoKIDFromJWT:
                return NSLocalizedString("Could not retrieve kid from JWT", comment: "")
            case .InvalidKID:
                return NSLocalizedString("Invalid Key ID", comment: "")
            case .InvalidSignature:
                return NSLocalizedString("Signature validation failed", comment: "")
            case .InvalidModulusOrExponent:
                return NSLocalizedString("Modulus or exponent from JWK could not be parsed", comment: "")
            case .ExpiredJWT:
                return NSLocalizedString("The JWT expired and is no longer valid", comment: "")
            case .IssuedInFuture:
                return NSLocalizedString("The JWT was issued in the future", comment: "")
            case .InvalidNonce:
                return NSLocalizedString("Invalid nonce", comment: "")
            case .InvalidClaim(value: let value):
                return NSLocalizedString("JWT does not contain \"\(value)\" in the payload", comment: "")
            }
    }
}
