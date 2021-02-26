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

public protocol RSAPKCS1SignerProtocol: TokenSigner {
    var hashFunction: SignatureAlgorithm.HashFunction { get }
    var key: RSAKey { get }

    init(hashFunction: SignatureAlgorithm.HashFunction, key: RSAKey)

    var signatureAlgorithm: SignatureAlgorithm { get }

    func sign(_ input: Data) throws -> Data
}

public extension RSAPKCS1SignerProtocol {
    var signatureAlgorithm: SignatureAlgorithm {
        return .rsassa_PKCS1(self.hashFunction)
    }
}

public class RSAPKCS1SignerFactory {
    public static func createSigner(hashFunction: SignatureAlgorithm.HashFunction, key: RSAKey) -> RSAPKCS1SignerProtocol {
#if os(iOS) || os(watchOS)
        return RSAPKCS1SignerIOS(hashFunction: hashFunction, key: key)
#elseif os(OSX)
        return RSAPKCS1SignerMacOS(hashFunction: hashFunction, key: key)
#endif
    }
}
