public enum OktaAPIError: Error {
    case NoWellKnown
    case NoJWKSEndpoint
    case NoKey
}

extension OktaAPIError: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .NoWellKnown:
                return NSLocalizedString("Could not retrieve well-known metadata endpoint", comment: "")
            case .NoJWKSEndpoint:
                return NSLocalizedString("Unable to capture jwks_uri from well-known endpoint", comment: "")
            case .NoKey:
                return NSLocalizedString("Unable to find JWK for Key ID", comment: "")
            }
    }
}
