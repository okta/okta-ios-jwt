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

import Foundation

public protocol RSAPKCS1Verifier : SignatureValidator {
    var hashFunction: SignatureAlgorithm.HashFunction { get }
    var key: RSAKey { get }

    init(key: RSAKey, hashFunction: SignatureAlgorithm.HashFunction)

    func canVerifyWithSignatureAlgorithm(_ alg: SignatureAlgorithm) -> Bool

    func verify(_ input: Data, signature: Data) -> Bool
}

public extension RSAPKCS1Verifier {
    func canVerifyWithSignatureAlgorithm(_ alg: SignatureAlgorithm) -> Bool {
        if case SignatureAlgorithm.rsassa_PKCS1(self.hashFunction) = alg {
            return true
        }
        return false
    }
}

public class RSAPKCS1VerifierFactory {
    public static func createVerifier(key: RSAKey, hashFunction: SignatureAlgorithm.HashFunction) -> RSAPKCS1Verifier {
#if os(iOS)
        return RSAPKCS1VerifierIOS(key: key, hashFunction: hashFunction)
#elseif os(OSX)
        return RSAPKCS1VerifierMacOS(key: key, hashFunction: hashFunction)
#endif
    }
}
