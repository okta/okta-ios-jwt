import UIKit
import XCTest
@testable import OktaJWT

class IdTokenTests: XCTestCase {
    var jwts: [String: Any] = [:]
    override func setUp() {
        super.setUp()
        OktaKeychain.clearAll()
        jwts = TestUtils().jwts
    }
    
    override func tearDown() {
        super.tearDown()
        RSAKey.removeKeyWithTag("com.okta.jwt.mlu6Wdq5u6GrlH_J3jZdGLg-yPOnVh3_gH8Knf6IPlU")
    }
    
    func testInvalidIssuerForIdToken() {
        let options = [ "issuer": "https://myrealsite.com"]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Token issuer does not match the valid issuer")
        }
    }
    
    func testInvalidAudienceForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "abc123"
        ]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Token audience does not match the valid audience")
        }
    }
    
    func testInvalidModulusForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs"
            ] as [String : Any]
        
        let validator = OktaJWTValidator(options, jwk: TestUtils.invalidJWK)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Modulus or exponent from JWK could not be parsed")
        }
    }
    
    func testInvalidKeyIDForIdTokenGivenJWK() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs"
        ]
        
        let validator = OktaJWTValidator(options, jwk: TestUtils.invalidJWKID)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Invalid Key ID")
        }
    }
    
    func testInvalidSignatureForIdTokenGivenJWK() {
        RSAKey.removeKeyWithTag("com.okta.jwt.mlu6Wdq5u6GrlH_J3jZdGLg-yPOnVh3_gH8Knf6IPlU")
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs"
        ]
        
        let validator = OktaJWTValidator(options, jwk: TestUtils.invalidJWKModulus)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Signature validation failed")
        }
    }
    
    func testExpiredForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": true
        ] as [String: Any]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "The JWT expired and is no longer valid")
        }
    }
    
    func testIssuedAtForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "iat": true,
            "leeway": -800000000
            ] as [String : Any]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "The JWT was issued in the future")
        }
    }
    
    func testInvalidNonceForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false,
            "nonce": "fakeNonce"
            ] as [String : Any]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Invalid nonce")
        }
    }
    
    func testMiscValuesFailureForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false,
            "nonce": "2C2C7E93-04A7-4249-9236-488C14CD34C6",
            "test1": "abc123",
            ] as [String : Any]
        
        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "JWT does not contain \"abc123\" in the payload")
        }
    }
    
    func testMiscValuesSuccessForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false,
            "nonce": "2C2C7E93-04A7-4249-9236-488C14CD34C6",
            "sub": "00u70qxs5zkVyPBT50h7",
            ] as [String : Any]
        
        let validator = OktaJWTValidator(options)
        
        guard let isValid = try? validator.isValid(jwts["OktaIDToken"] as! String) else {
            XCTFail()
            return
        }
        XCTAssertEqual(isValid, true)
    }
    
    func testSuccessForIdTokenGivenJWK() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": "GJv1mKQtUAUbTalBeQLs",
            "exp": false,
            "iat": false,
            "nonce": "2C2C7E93-04A7-4249-9236-488C14CD34C6",
            ] as [String : Any]
        
        let validator = OktaJWTValidator(options, jwk: TestUtils.exampleJWK)
        
        guard let isValid = try? validator.isValid(jwts["OktaIDToken"] as! String) else {
            XCTFail()
            return
        }
        XCTAssertEqual(isValid, true)
    }
    
    func testSuccessForIdTokenGivenJWKNoVerification() {
        let options: [String: Any] = [:]
        
        let validator = OktaJWTValidator(options, jwk: TestUtils.exampleJWK)
        
        guard let isValid = try? validator.isValid(jwts["OktaIDToken"] as! String) else {
            XCTFail()
            return
        }
        XCTAssertEqual(isValid, true)
    }
}
