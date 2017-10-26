import UIKit
import XCTest
@testable import OktaJWT

class MiscTests: XCTestCase {
    var jwts: [String: Any] = [:]

    override func setUp() {
        super.setUp()
        jwts = TestUtils().jwts
    }

    override func tearDown() {
        super.tearDown()
    }

    func testValidatorOptions() {
        let options = [ "issuer": TestUtils.issuer ]

        let validator = OktaJWTValidator(options)
        XCTAssertNotNil(validator)
    }
    
    func testHasTrailingSlash() {
        let issuer = Utils.removeTrailingSlash(TestUtils.issuer + "/")
        XCTAssertEqual(TestUtils.issuer, issuer)
    }

    func testHasNoTrailingSlash() {
        let issuer = Utils.removeTrailingSlash(TestUtils.issuer)
        XCTAssertEqual(issuer, "https://example.oktapreview.com/oauth2/default")
    }

    func testStoringAndRemoveFromKeychain() {
        let keyId = "abc12345"
        OktaKeychain.set(key: keyId, "testValue")
        XCTAssertEqual(OktaKeychain.get(keyId), "testValue")
        OktaKeychain.remove(keyId)
        XCTAssertEqual(OktaKeychain.get(keyId), nil)
    }
    
    func testInvalidJWT() {
        let options = [ "issuer": TestUtils.issuer ]

        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid("ey.xx.yy")) { error in
            let desc = error as! OktaJWTValidationError
            XCTAssertEqual(desc.localizedDescription, "String injected is not formatted as a JSON Web Token")
        }
    }
    
    func testNonSupportedAlgJWT() {
        let options = [ "issuer": TestUtils.issuer ]

        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["HS256JWT"] as! String)) { error in
            let desc = error as! OktaJWTValidationError
            XCTAssertEqual(desc.localizedDescription, "The JWT algorithm HS256 is not supported at this time")
        }
    }
    
    func testNoKIDInHeaderJWT() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.audience
        ]

        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["RS256JWT"] as! String)) { error in
            let desc = error as! OktaJWTValidationError
            XCTAssertEqual(desc.localizedDescription, "Could not retrieve kid from JWT")
        }
    }
    
    func testMySiteJWT() {
        let options = [
            "issuer": "https://mysite.com",
            "audience": TestUtils.audience
        ]

        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["NoDiscoveryJWT"] as! String)) { error in
            let desc = error as! OktaAPIError
            XCTAssertEqual(desc.localizedDescription, "Could not retrieve well-known metadata endpoint")
        }
    }
}
