/*
* Copyright (c) 2020, Okta, Inc. and/or its affiliates. All rights reserved.
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

public struct RSAPKCS1VerifierMacOS: RSAPKCS1VerifierProtocol {
    public let hashFunction: SignatureAlgorithm.HashFunction
    public let key: RSAKey

    public init(key: RSAKey, hashFunction: SignatureAlgorithm.HashFunction) {
        self.hashFunction = hashFunction
        self.key = key
    }

    public func verify(_ input: Data, signature: Data) -> Bool {
        let signedDataHash = (input as NSData).jwt_shaDigest(withSize: self.hashFunction.rawValue)
        let padding = paddingForHashFunction(self.hashFunction)
        
        switch self.hashFunction.rawValue {
        case 256:
             return SecKeyVerifySignature(key.value, .rsaSignatureDigestPKCS1v15SHA256, signedDataHash as CFData, signature as CFData, nil)
        case 384:
            return SecKeyVerifySignature(key.value, .rsaSignatureDigestPKCS1v15SHA384, signedDataHash as CFData, signature as CFData, nil)
        case 512:
            return SecKeyVerifySignature(key.value, .rsaSignatureDigestPKCS1v15SHA512, signedDataHash as CFData, signature as CFData, nil)
        default:
            return false
        }
    }
}
