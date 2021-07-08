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
#if SWIFT_PACKAGE
@testable import OktaJWT
#else
@testable import OktaJWTLib
#endif

class IdTokenTests: XCTestCase {
    var jwts: [String: Any] = [:]
    override func setUp() {
        super.setUp()
        OktaKeychain.clearAll()
        jwts = TestUtils().jwts
    }

    override func tearDown() {
        super.tearDown()
        RSAKey.removeKeyWithTag("com.okta.jwt.0XoqZmZm5nBQtRxTwq5T29s0TzqtDj0zsr8lFHp98vg", keyStorageManager: nil)
    }

    func testInvalidIssuerForIdToken() {
        let options = [ "issuer": "https://myrealsite.com"]

        var validator = OktaJWTValidator(options)
        validator.keyStorageManager = MockKeyStorageManager()
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
            "audience": TestUtils.clientId
        ]

        let validator = OktaJWTValidator(options, jwk: TestUtils.invalidJWK)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Modulus or exponent from JWK could not be parsed")
        }
    }

    func testInvalidKeyIDForIdTokenGivenJWK() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.clientId
        ]

        let validator = OktaJWTValidator(options, jwk: TestUtils.invalidJWKID)
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Invalid Key ID")
        }
    }

    func testInvalidSignatureForIdTokenGivenJWK() {
        RSAKey.removeKeyWithTag("com.okta.jwt.0XoqZmZm5nBQtRxTwq5T29s0TzqtDj0zsr8lFHp98vg", keyStorageManager: nil)
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.clientId
        ]

        var validator = OktaJWTValidator(options, jwk: TestUtils.invalidJWKModulus)
        validator.keyStorageManager = MockKeyStorageManager()
        
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Signature validation failed")
        }
    }

    func testExpiredForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.clientId,
            "exp": true
        ] as [String: Any]

        var validator = OktaJWTValidator(options)
        validator.keyStorageManager = MockKeyStorageManager()
        
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "The JWT expired and is no longer valid")
        }
    }

    func testIssuedAtForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.clientId,
            "iat": true,
            "leeway": -800000000
        ] as [String : Any]

        var validator = OktaJWTValidator(options)
        validator.keyStorageManager = MockKeyStorageManager()
        
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "The JWT was issued in the future")
        }
    }

    func testInvalidNonceForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.clientId,
            "exp": false,
            "iat": false,
            "nonce": "fakeNonce"
        ] as [String : Any]
        
        var validator = OktaJWTValidator(options)
        validator.keyStorageManager = MockKeyStorageManager()

        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "Invalid nonce")
        }
    }

    func testMiscValuesFailureForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.clientId,
            "exp": false,
            "iat": false,
            "nonce": "A3ADBD9B-F3B4-4FBD-B51C-2334F1359BEC",
            "test1": "abc123"
        ] as [String : Any]

        var validator = OktaJWTValidator(options)
        validator.keyStorageManager = MockKeyStorageManager()
        
        XCTAssertThrowsError(try validator.isValid(jwts["OktaIDToken"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "JWT does not contain \"abc123\" in the payload")
        }
    }

    func testMiscValuesSuccessForIdToken() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.clientId,
            "exp": false,
            "iat": false,
            "nonce": "A3ADBD9B-F3B4-4FBD-B51C-2334F1359BEC",
            "sub": "00ue1gi0ptZpa67pU0h7"
        ] as [String : Any]

        var validator = OktaJWTValidator(options)
        validator.keyStorageManager = MockKeyStorageManager()

        guard let isValid = try? validator.isValid(jwts["OktaIDToken"] as! String) else {
            return XCTFail("VALID token was returned as INVALID.")
        }
        XCTAssertEqual(isValid, true)
    }

    func testSuccessForIdTokenGivenJWK() {
        let options = [
            "issuer": TestUtils.issuer,
            "audience": TestUtils.clientId,
            "exp": false,
            "iat": false,
            "nonce": "A3ADBD9B-F3B4-4FBD-B51C-2334F1359BEC"
        ] as [String : Any]

        var validator = OktaJWTValidator(options, jwk: TestUtils.exampleJWK)
        validator.keyStorageManager = MockKeyStorageManager()

        guard let isValid = try? validator.isValid(jwts["OktaIDToken"] as! String) else {
            return XCTFail()
        }
        XCTAssertEqual(isValid, true)
    }

    func testSuccessForIdTokenGivenJWKNoVerification() {
        let options: [String: Any] = [:]

        var validator = OktaJWTValidator(options, jwk: TestUtils.exampleJWK)
        validator.keyStorageManager = MockKeyStorageManager()

        guard let isValid = try? validator.isValid(jwts["OktaIDToken"] as! String) else {
            return XCTFail("VALID token was returned as INVALID.")
        }
        XCTAssertEqual(isValid, true)
    }
}
