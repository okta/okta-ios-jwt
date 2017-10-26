import UIKit
import XCTest
@testable import OktaJWT

class JWTTests: XCTestCase {
    var jwts: [String: Any] = [:]
    
    override func setUp() {
        super.setUp()
        OktaKeychain.clearAll()
        jwts = TestUtils().jwts
    }
    
    override func tearDown() {
        super.tearDown()
        RSAKey.removeKeyWithTag("com.okta.jwt.QViC9OB_fQO3d5ktIegAWaR0SJHJqtFRZRSjqTI5m1M")
    }
    
    func testInvalidJWT() {
        let options = [ "issuer": TestUtils.issuer ]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid("ey.xx.yy")) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "String injected is not formatted as a JSON Web Token")
        }
    }
    
    func testInvalidIssuerForJWT() {
        let options = [ "issuer": "https://myrealsite.com"]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWT"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(
                desc.localizedDescription,
                "Token issuer does not match the valid issuer"
            )
        }
    }
    
    func testInvalidAudienceForJWT() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "abc123"
        ]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWT"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(
                desc.localizedDescription,
                "Token audience does not match the valid audience"
            )
        }
    }
    
    func testInvalidSignatureForJWTByInjectingJWK() {
        let options = [
            "issuer" : TestUtils.issuer,
            "audience": TestUtils.audience
        ]
        
        let validator = OktaJWTValidator(options, jwk: TestUtils.invalidJWKID)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWT"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Invalid Key ID")
        }
    }
    
    
    func testInvalidSignatureForJWTGivenJWK() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.audience
        ]
        
        let validator = OktaJWTValidator(options, jwk: TestUtils.invalidJWKModulusForJWT)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWT"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Signature validation failed")
        }
    }
    
    func testExpiredForJWT() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.audience,
            "exp": true
            ] as [String: Any]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWT"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "The JWT expired and is no longer valid")
        }
    }
    
    func testIssuedAtForJWT() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.audience,
            "iat": true,
            "leeway": -800000000
            ] as [String : Any]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWT"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "The JWT was issued in the future")
        }
    }
    
    
    func testMiscValuesFailureForJWT() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.audience,
            "exp": false,
            "iat": false,
            "test1": "abc123",
            ] as [String : Any]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWT"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "JWT does not contain \"abc123\" in the payload")
        }
    }
    
    func testValidationByInjectingRSAKey() {
        let options = [
            "issuer" : TestUtils.issuer,
            "audience": TestUtils.audience,
            "cid": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false
            ] as [String: Any]
        
        let validator = OktaJWTValidator(options, key: TestUtils.exampleRSAKey!)
        guard let isValid = try? validator.isValid(jwts["OktaJWT"] as! String) else {
            XCTFail()
            return
        }
        XCTAssertEqual(isValid, true)
    }
    
}
