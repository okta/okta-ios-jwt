/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import XCTest
@testable import OktaJWTLib

// TODO: port tests to MacOS
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
            "test1": "abc123"
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
            "cid": TestUtils.clientId,
            "exp": false,
            "iat": false
        ] as [String: Any]

        let validator = OktaJWTValidator(options, key: TestUtils.exampleRSAKey!)
        guard let isValid = try? validator.isValid(jwts["OktaJWT"] as! String) else {
            return XCTFail("VALID token was returned as INVALID.")
        }
        XCTAssertEqual(isValid, true)
    }

    func testValidTypeHeaderForJWT() {
        let options = [
            "iat": false,
            "typ": "jwt",
            "leeway": -800000000
        ] as [String : Any]

        let validator = OktaJWTValidator(options, jwk:TestUtils.validJWKCustomizeTypeHeader)

        guard let isValid = try? validator.isValid(jwts["OktaJWTTypeHeader"] as! String) else {
            return XCTFail("VALID token was returned as INVALID.")
        }
        XCTAssertEqual(isValid, true)
    }

    func testInvalidTypeHeaderForJWT() {
        let options = [
            "iat": false,
            "typ": "jwt-invalid",
            "leeway": -800000000
        ] as [String : Any]

        let validator = OktaJWTValidator(options, jwk:TestUtils.validJWKCustomizeTypeHeader)

        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWTTypeHeader"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "String injected is not formatted as a JSON Web Token")
        }
    }

    func testValidCustomTypeHeaderForJWT() {
        let options = [
            "iat": false,
            "typ": "okta-devicebind+jwt",
            "leeway": -800000000
        ] as [String : Any]

        let validator = OktaJWTValidator(options, jwk:TestUtils.validJWKCustomizeTypeHeader)

        guard let isValid = try? validator.isValid(jwts["OktaJWTTypeHeaderCustom"] as! String) else {
            return XCTFail("VALID token was returned as INVALID.")
        }
        XCTAssertEqual(isValid, true)
    }

    func testInvalidCustomTypeHeaderForJWT() {
        let options = [
            "iat": false,
            "typ": "jwt",
            "leeway": -800000000
        ] as [String : Any]

        let validator = OktaJWTValidator(options, jwk:TestUtils.validJWKCustomizeTypeHeader)

        XCTAssertThrowsError(try validator.isValid(jwts["OktaJWTTypeHeaderCustom"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "String injected is not formatted as a JSON Web Token")
        }
    }
}
