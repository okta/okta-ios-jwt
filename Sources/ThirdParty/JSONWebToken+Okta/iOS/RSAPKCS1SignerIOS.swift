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

public struct RSAPKCS1SignerIOS: RSAPKCS1SignerProtocol {
    enum Error: Swift.Error {
        case securityError(OSStatus)
    }

    public let hashFunction: SignatureAlgorithm.HashFunction
    public let key: RSAKey

    public init(hashFunction: SignatureAlgorithm.HashFunction, key: RSAKey) {
        self.hashFunction = hashFunction
        self.key = key
    }

    public func sign(_ input: Data) throws -> Data {
        let signedDataHash = (input as NSData).jwt_shaDigest(withSize: self.hashFunction.rawValue)
        let padding = paddingForHashFunction(self.hashFunction)

        var result = Data(count: SecKeyGetBlockSize(self.key.value))
        var resultSize = result.count
        let status = result.withUnsafeMutableBytes { resultBytes in
            SecKeyRawSign(key.value, padding, (signedDataHash as NSData).bytes.bindMemory(to: UInt8.self, capacity: signedDataHash.count), signedDataHash.count, UnsafeMutablePointer<UInt8>(resultBytes), &resultSize)
        }

        switch status {
        case errSecSuccess:
            return result.subdata(in: 0..<resultSize)
        default:
            throw Error.securityError(status)
        }
    }
}

