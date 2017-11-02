public enum OktaJWTSigningError: Error {
    case SigningError(String)
    case NonSupportedAlg(String)
}

extension OktaJWTSigningError: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .SigningError(error: let error):
                return NSLocalizedString(error, comment: "")
            case .NonSupportedAlg(alg: let alg):
                return NSLocalizedString("The signing algorithm \(alg) is not supported at this time", comment: "")
        }
    }
}

