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
        XCTAssertEqual(issuer, "https://demo-org.oktapreview.com/oauth2/default")
    }

    // Warning: SPM and macOS (even with hosted app) don't support Keychain during unit tests.
    #if !SWIFT_PACKAGE && os(iOS)
    func testStoringAndRemoveFromKeychain() {
        let keyId = "abc12345"
        OktaKeychain.set(key: keyId, "testValue")
        XCTAssertEqual(OktaKeychain.get(keyId), "testValue")
        OktaKeychain.remove(keyId)
        XCTAssertEqual(OktaKeychain.get(keyId), nil)
    }
    #endif

    func testInvalidJWT() {
        let options = [ "issuer": TestUtils.issuer ]

        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid("ey.xx.yy")) { error in
            let desc = error as! OktaJWTVerificationError
            XCTAssertEqual(desc.localizedDescription, "String injected is not formatted as a JSON Web Token")
        }
    }

    func testNonSupportedAlgJWT() {
        let options = [ "issuer": TestUtils.issuer ]

        let validator = OktaJWTValidator(options)
        XCTAssertThrowsError(try validator.isValid(jwts["HS256JWT"] as! String)) { error in
            let desc = error as! OktaJWTVerificationError
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
            let desc = error as! OktaJWTVerificationError
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
            let apiError = error as! OktaAPIError
            XCTAssertEqual(apiError, .noWellKnown)
            XCTAssertEqual(apiError.localizedDescription, "Could not retrieve well-known metadata endpoint")
        }
    }

    func testRegisterOrUpdateKey() {
        #if os(iOS)
        let mockStorage = MockKeyStorageManager()
        let modulus = TestUtils.exampleJWK["n"]!
        let exponent = TestUtils.exampleJWK["e"]!
        let tag = "com.okta.jwt.0XoqZmZm5nBQtRxTwq5T29s0TzqtDj0zsr8lFHp98vg"

        // Store key to default storage
        var rsaKey = try? RSAKey.registerOrUpdateKey(modulus: Utils.base64URLDecode(modulus)!,
                                                     exponent: Utils.base64URLDecode(exponent)!,
                                                     tag: tag,
                                                     keyStorageManager: nil)
        XCTAssertNotNil(rsaKey)
        var dataFromStorage = try? mockStorage.data(with: tag)
        XCTAssertTrue(dataFromStorage?.isEmpty ?? false)

        // Store key to custom storage
        rsaKey = try? RSAKey.registerOrUpdateKey(modulus: Utils.base64URLDecode(modulus)!,
                                                 exponent: Utils.base64URLDecode(exponent)!,
                                                 tag: tag,
                                                 keyStorageManager: mockStorage)
        XCTAssertNotNil(rsaKey)
        dataFromStorage = try? mockStorage.data(with: tag)
        XCTAssertNotNil(dataFromStorage)
        XCTAssertTrue(dataFromStorage!.count > 0)
        #endif
    }
}
