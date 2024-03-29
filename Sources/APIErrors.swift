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

public enum OktaAPIError: Error {
    case noWellKnown
    case noJWKSEndpoint
    case noKey
    case offline
}

extension OktaAPIError: LocalizedError {
    public var errorDescription: String? {
        switch self {
            case .noWellKnown:
                return NSLocalizedString("Could not retrieve well-known metadata endpoint", comment: "")
            case .noJWKSEndpoint:
                return NSLocalizedString("Unable to capture jwks_uri from well-known endpoint", comment: "")
            case .noKey:
                return NSLocalizedString("Unable to find JWK for Key ID", comment: "")
            case .offline:
                return NSLocalizedString("Internet connection could not been established", comment: "")
            }
    }
}
