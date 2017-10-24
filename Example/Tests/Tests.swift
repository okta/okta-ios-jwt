import UIKit
import XCTest
@testable import OktaJWT

class Tests: XCTestCase {
    var issuer: String = ""
    var basicJWT: String = ""
    var oktaIdToken: String = ""
    var oktaJWT: String = ""
    var exampleJWK: [String: String] = [:]
    var invalidJWK: [String: String] = [:]
    var exampleRSAKey: RSAKey?

    override func setUp() {
        super.setUp()
        OktaKeychain.clearAll()

        // Init vars
        self.issuer = "https://example.oktapreview.com/"

        self.basicJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3" +
                        "ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM" +
                        "7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"

        self.oktaIdToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IlFWaUM5T0JfZlFPM2Q1a3RJZWdBV2FSMFNKSEpxd" +
            "EZSWlJTanFUSTVtMU0ifQ.eyJzdWIiOiIwMHU3MHF4czV6a1Z5UEJUNTBoNyIsIm5hbWUi" +
            "OiJKb3JkYW4gTWVsYmVyZyIsInZlciI6MSwiaXNzIjoiaHR0cHM6Ly9leGFtcGxlLm9rdG" +
            "FwcmV2aWV3LmNvbSIsImF1ZCI6IkdKdjFtS1F0VUFVYlRhbEJlUUxzIiwiaWF0IjoxNTA4" +
            "ODg2OTg2LCJleHAiOjE1MDg4OTA1ODYsImp0aSI6IklELmU2SlI4NFZnQXcwRG1TOF9XWF" +
            "hHQV9UOHpINGZFYXFWY0F1VW5sOUI5ZEUiLCJhbXIiOlsicHdkIl0sImlkcCI6IjAwbzVp" +
            "dnN2cWxKU0pWQm1lMGg3Iiwibm9uY2UiOiJBQUE4QTFENS04OEZCLTQ2MUEtQjIyNS1EMU" +
            "I0RTVFQzdBQjQiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJqb3JkYW5Ab2t0YS5jb20iLCJh" +
            "dXRoX3RpbWUiOjE1MDg4ODY5ODUsImF0X2hhc2giOiJhNU4yQlgxTFJMSmY4M0VQM2VoSj" +
            "NnIn0.VuY0FMvOKHFSCyMCdFfnF5Ve4TT5qDUNo9PUMuyvZwgAmjQVJkd6H-tnzkPyFXAB" +
            "C3Q8wTgHAQerzvacY1tVZCLgRX6xAW8GRVewVtLMhYtcIjwzV29jjL4gcb12OvkRJyzOol" +
            "40j3NgadumN-9gUGuDn3G1qiFxv6BOctUFmOA3Nb_UTeTI8xoRvDlV6psd5GG-zBQnkkU7" +
            "oEx2EvJq8hN0LNkT1fKoeHkpJKj6GYJdoJ3sLdk2A5l_2_xJtUXktHSlQSf03sit50IqLb" +
            "HIM2VhVgkjarbuQYMA2LO1c6Jm2SsgPCfFiH9Pq_j5-8TG6Lw-r3XmMci1A-9HbfLdjg"

        self.oktaJWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6Ino3MWZMWnJsaTY2bEFSeUxWWjVjVmR3Zkp" +
            "QSC1HRmdhTEdCZ3RlZ3ZTejQifQ.eyJ2ZXIiOjEsImp0aSI6IkFULnVkcmxkOTFfZnpFNkdILT" +
            "lCcWpiZ0xYYmNZeFYxZHhNQkNiMldkY3hrMFEuRys4bWFEckg2NUxBemJhT3lsU3hxWU5xckVs" +
            "ZE82clo4eVVkRDZnZEF1az0iLCJpc3MiOiJodHRwczovL2V4YW1wbGUub2t0YXByZXZpZXcuY2" +
            "9tIiwiYXVkIjoiaHR0cHM6Ly9leGFtcGxlLm9rdGFwcmV2aWV3LmNvbSIsInN1YiI6ImpvcmRh" +
            "bkBva3RhLmNvbSIsImlhdCI6MTUwODk0ODc1NSwiZXhwIjoxNTA4OTUyMzU1LCJjaWQiOiJHSn" +
            "YxbUtRdFVBVWJUYWxCZVFMcyIsInVpZCI6IjAwdTcwcXhzNXprVnlQQlQ1MGg3Iiwic2NwIjpb" +
            "Im9mZmxpbmVfYWNjZXNzIiwicHJvZmlsZSIsIm9wZW5pZCJdfQ.N0YnirroxOaHDjK9_dja_h-" +
            "Fy0GKXuOFnejczWkEgs4KFJxvZW61oKGdEl_h9bzKID38S_FM-dThFfk8B1q0Abm34PJ2gg2K2" +
            "BG_tZcQVHzeYDpfGdvt7NXdjV3oamHU9qrH3wD4sSSTwLk_SkZpHqIAUX6Roe-ClKVS8Vy7BJx" +
            "8JefXGpqV7HXZfeKpnIxe9KPoHZky8zsgJZrQ4NefB_bqv2N8VAUSuBMcGdlR1UQLFbK1aYgjl" +
            "gtG73ltTHByLsbioJI1bwsgyc7-3hp56RzMLvnccX8apaxnCid7VAiDiQIWAfX0mIjSrl7OUQR" +
            "or2XXPUY7YdLXNUw5YvukRw"

        self.exampleJWK = [
            "alg": "RS256",
            "e": "AQAB",
            "n": "kDL-uc8IguAoTa4WHNdMIzMwpYKCtTibRr1UbgyKVT82kvV0Auwb-j3eoEs151vqFVEPudS0fK1aV" +
                "dyOVcdA_zkgChqJRNJypw9cwuJnsyApYzcM6_-JxN2aERlb1CEzP9T5vC_-S1ZAaLmeNAFB8CJ8LX" +
                "Z2lK2iSUn83B_7I-ealvkaIechjBB4Sz29aDDHMnlfth9DeC7wIwHLTCA6d8NEdUOAL9UdZWw1afK" +
                "-Uh72E-q7-1tNZBo9k3413grsVL7tnsuZjw7RHfZeXnMbBytR-gdqSJ8UeUZ-HdVE7SNdDG7NR3Mx" +
            "KgjNR7kNfOl4BYEw_cWLicRd413gqyYAkQ",
            "kid": "QViC9OB_fQO3d5ktIegAWaR0SJHJqtFRZRSjqTI5m1M",
            "kty": "RSA",
            "use": "sig"
        ]

        self.invalidJWK = [
            "alg": "RS256",
            "e": "AQAB",
            "n": "someValue",
            "kid": "fakeKid",
            "kty": "RSA",
            "use": "sig"
        ]

        self.exampleRSAKey = self.createRSAKey(modulus: self.exampleJWK["n"]!, exponent: self.exampleJWK["e"]!)
    }

    override func tearDown() {
        super.tearDown()
        RSAKey.removeKeyWithTag("com.okta.jwt.QViC9OB_fQO3d5ktIegAWaR0SJHJqtFRZRSjqTI5m1M")
    }

    func createRSAKey(modulus: String, exponent: String) -> RSAKey? {
        let tag = "com.okta.jwt.QViC9OB_fQO3d5ktIegAWaR0SJHJqtFRZRSjqTI5m1M"
        return try? RSAKey.registerOrUpdateKey(
            modulus: Utils.base64URLDecode(modulus)!,
            exponent: Utils.base64URLDecode(exponent)!,
            tag: tag
        )
    }

    /// UTILS
    func testHasTrailingSlash() {
        let issuer = Utils.removeTrailingSlash(self.issuer + "/")
        XCTAssertEqual(self.issuer, issuer)
    }

    func testHasNoTrailingSlash() {
        let issuer = Utils.removeTrailingSlash(self.issuer)
        XCTAssertEqual(issuer, "https://example.oktapreview.com")
    }

    /// JWT Validation Tests
    func testValidatorOptions() {
        let options = [ "issuer": self.issuer ]
        let validator = OktaJWTValidator(options)
        XCTAssertNotNil(validator)
    }

    /// ID Token Validation Tests
    func testInvalidAudienceForIdToken() {
        let options = [
            "issuer": self.issuer,
            "audience": "abc123"
        ]
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(self.oktaJWT)) { error in
            XCTAssertNotNil(error as? OktaError)
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "Token audience: [\"https://example.oktapreview.com\"] does not match the valid audience")
        }
    }

    func testExpiredIdToken() {
        let options = [
            "issuer": self.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs"
        ]
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(self.oktaIdToken)) { error in
            XCTAssertNotNil(error as? OktaError)
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "The JWT expired and is no longer valid")
        }
    }

    func testIssuedAtIdToken() {
        let options = [
            "issuer": self.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "leeway": -800000000
            ] as [String : Any]
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(self.oktaIdToken)) { error in
            XCTAssertNotNil(error as? OktaError)
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "The JWT was issued in the future")
        }
    }

    func testInvalidNonceForIdToken() {
        let options = [
            "issuer": self.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false,
            "nonce": "fakeNonce"
            ] as [String : Any]
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(self.oktaIdToken)) { error in
            XCTAssertNotNil(error as? OktaError)
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "Invalid JWT nonce")
        }
    }

    func testMiscValuesFailureForIdToken() {
        let options = [
            "issuer": self.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false,
            "nonce": "AAA8A1D5-88FB-461A-B225-D1B4E5EC7AB4",
            "test1": "abc123",
            ] as [String : Any]
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(self.oktaIdToken)) { error in
            XCTAssertNotNil(error as? OktaError)
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "JWT does not contain \"abc123\" in the payload")
        }
    }

    func testMiscValuesSuccessForIdToken() {
        let options = [
            "issuer": self.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false,
            "nonce": "AAA8A1D5-88FB-461A-B225-D1B4E5EC7AB4",
            "sub": "00u70qxs5zkVyPBT50h7",
            ] as [String : Any]
        let validator = OktaJWTValidator(options)
        
        guard let isValid = try? validator.isValid(self.oktaIdToken) else {
            XCTFail()
            return
        }
        XCTAssertEqual(isValid, true)
    }

    func testInvalidKeyIDForIdToken() {
        let options = [
            "issuer": self.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs"
        ]
        let validator = OktaJWTValidator(options, jwk: self.invalidJWK)
        XCTAssertThrowsError(try validator.isValid(self.oktaIdToken)) { error in
            XCTAssertNotNil(error as? OktaError)
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "Modulus or exponent from JWK could not be parsed")
        }
    }

    /// Access Token Validation Tests
    func testInvalidIssuerForJWT() {
        let options = [ "issuer": "https://myrealsite.com"]
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(self.oktaJWT)) { error in
            XCTAssertNotNil(error as? OktaError)
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "Token issuer: https://example.oktapreview.com does not match the valid issuer")
        }
    }

    func testInvalidAudienceForJWT() {
        let options = [
            "issuer": self.issuer,
            "audience": "abc123"
        ]
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(self.oktaJWT)) { error in
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "Token audience: [\"https://example.oktapreview.com\"] does not match the valid audience")
        }
    }

    func testInvalidSignatureByInjectingJWK() {
        let options = [
            "issuer" : self.issuer,
            "audience": self.issuer,
            "cid": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false
        ] as [String: Any]
        let validator = OktaJWTValidator(options, jwk: self.invalidJWK)
        XCTAssertThrowsError(try validator.isValid(self.oktaJWT)) { error in
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "Modulus or exponent from JWK could not be parsed")
        }
    }

    func testInvalidSignatureByInjectingRSAKey() {
        let options = [
            "issuer" : self.issuer,
            "audience": self.issuer,
            "cid": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false
            ] as [String: Any]
        let validator = OktaJWTValidator(options, key: self.exampleRSAKey!)
        XCTAssertThrowsError(try validator.isValid(self.oktaJWT)) { error in
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "Signature validation failed")
        }
    }

    func testInvalidJWT() {
        let options = [ "issuer": self.issuer ]
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid("ey.xx.yy")) { error in
            let desc = error as! OktaError
            XCTAssertEqual(desc.localizedDescription, "String injected is not formatted as a JSON Web Token")
        }
    }

    func testStoringAndRemoveFromKeychain() {
        let keyId = "abc12345"
        OktaKeychain.set(key: keyId, "testValue")
        XCTAssertEqual(OktaKeychain.get(keyId), "testValue")
        OktaKeychain.remove(keyId)
        XCTAssertEqual(OktaKeychain.get(keyId), nil)

    }
}
