import UIKit
import XCTest
@testable import OktaJWT

class JWTSigningTests: XCTestCase {
    override func setUp() {
        super.setUp()
    }

    override func tearDown() {
        super.tearDown()
        RSAKey.removeKeyWithTag("testKey")
    }

    func testSigningPayloadInit() {
        let payload = [
            "iss" : TestUtils.issuer,
            "aud": TestUtils.audience,
        ]

        let key = TestUtils.exampleRSAKey

        let signer = OktaJWTSigner(payload, signType: .RSA, key: key!)
        XCTAssertNotNil(signer)
    }

    func testSigningPayloadWithPublicKey() {
        let payload = [
            "iss" : TestUtils.issuer,
            "aud": TestUtils.audience,
            ]

        let publicKey = TestUtils.exampleRSAKey

        let signer = OktaJWTSigner(payload, signType: .RSA, key: publicKey!)

        XCTAssertThrowsError(try signer.jwt()){ error in
            let desc = error as! OktaJWTSigningError
            XCTAssertEqual(desc.localizedDescription, "Error signing JWT")
        }
    }

    func testSigningPayloadWithPrivateKey() {
        let payload = [
            "iss" : TestUtils.issuer,
            "aud": TestUtils.audience
        ]

        let privateKey = OktaKeychain.createPrivateRSAKey(tag: "testKey")
        let publicKey = RSAKey.registeredKeyWithTag("testKey")

        let signer = OktaJWTSigner(payload, signType: .RSA, key: privateKey!)

        guard let jwt = try? signer.jwt() else {
            return XCTFail()
        }

        let validator = OktaJWTValidator(payload, key: publicKey!)

        guard let isValid = try? validator.isValid(jwt) else {
            return XCTFail()
        }
        XCTAssertEqual(isValid, true)
        RSAKey.removeKeyWithTag("testKey")
    }

    func testJWTCreationWithCustomClaim() {
        let payload = [
            "iss" : TestUtils.issuer,
            "aud": TestUtils.audience,
            "custom": "customValue"
        ]

        let privateKey = OktaKeychain.createPrivateRSAKey(tag: "testKey")
        let publicKey = RSAKey.registeredKeyWithTag("testKey")

        let signer = OktaJWTSigner(payload, signType: .RSA, key: privateKey!)

        guard let jwt = try? signer.jwt() else {
            return XCTFail()
        }

        let validator = OktaJWTValidator(payload, key: publicKey!)

        guard let isValid = try? validator.isValid(jwt) else {
            return XCTFail()
        }
        XCTAssertEqual(isValid, true)
        RSAKey.removeKeyWithTag("testKey")
    }

    func testComplexPayloadJWTCreation() {
        let nonce = UUID().uuidString
        let payload = [
            "tx": "abc123",
            "iss": TestUtils.issuer,
            "sub": "jmelberg",
            "aud": TestUtils.audience,
            "iat": Date(),
            "exp": Date().addingTimeInterval(300), // Now + 5 Mins
            "nbf": Date().addingTimeInterval(-300),  // Now - 5 mins,
            "jti": nonce
        ] as [String: Any]

        let privateKey = OktaKeychain.createPrivateRSAKey(tag: "testKey")
        let publicKey = RSAKey.registeredKeyWithTag("testKey")

        let signer = OktaJWTSigner(payload, signType: .RSA, key: privateKey!)

        guard let jwt = try? signer.jwt() else {
            return XCTFail()
        }

        let options = [
            "tx": "abc123",
            "iss": TestUtils.issuer,
            "sub": "jmelberg",
            "aud": TestUtils.audience,
            "iat": true,
            "exp": true,
            "leeway": 3000,
            "jti": nonce
        ] as [String: Any]
        
        let validator = OktaJWTValidator(options, key: publicKey!)
        
        guard let isValid = try? validator.isValid(jwt) else {
            return XCTFail()
        }
        XCTAssertEqual(isValid, true)
        RSAKey.removeKeyWithTag("testKey")

    }
}
