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
#if os(iOS)
import UIKit
#elseif os(watchOS)
import WatchKit
#endif

open class Utils: NSObject {

    /**
     Removes the trailing slash for the supplied issuer param.
     - parameters:
         - issuer: String representation of the issuer URL
     - returns:
     A modified String of the issuer without the trailing '/'
     */
    open class func removeTrailingSlash(_ issuer: String) -> String {
        return String(issuer.suffix(1)) == "/" ? String(issuer.dropLast()) : issuer
    }

    /**
     Base 64 URL decodes a given String.
     - parameters:
         - input: String representation of the value to be decoded
     - returns:
     The decoded String as a Data object
     */
    open class func base64URLDecode(_ input: String?) -> Data? {
        if input == nil { return nil }

        var base64 = input!
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        let length = Double(base64.lengthOfBytes(using: .utf8))
        let requiredLength = 4 * ceil(length / 4.0)
        let paddingLength = requiredLength - length
        if paddingLength > 0 {
            let padding = "".padding(toLength: Int(paddingLength), withPad: "=", startingAt: 0)
            base64 = base64 + padding
        }

        return Data(base64Encoded: base64, options: .ignoreUnknownCharacters)
    }

    /**
     Returns a hash function from a string formatted like the ALG section of a protected header.
     - parameters:
         - alg: the string representing the hash function
     - returns:
     the hash function or nil of not supported
     */
    open class func hashFunction(_ alg: String) -> SignatureAlgorithm.HashFunction? {
    switch alg {
        case "RS256":
            return .sha256
        case "RS384":
            return .sha384
        case "RS512":
            return .sha512
        default:
            return nil
        }
    }

    /**
     Parses the kid from the JWT header.
     - parameters:
         - header: Base64Decoded header object
     - returns:
     String representation of the JWT's kid
     */
    open class func getKeyIdFromHeader(_ header: Data) -> String? {
        let json = try? JSONSerialization.jsonObject(with: header, options: []) as? [String: Any]
        if let kid = json?["kid"] {
            // Return the kid from the header object
            return String(describing: kid)
        }

        return nil
    }

    /**
     Returns the matching key from the jwks_uri endpoint.
     - parameters:
         - kid: String representation of the kid to find
         - keysEndpoint: String of the endpoint to request the JWKs
     - returns:
     A JSON Web Key dictionary matching the JWTs kid
     */
    open class func getKeyFromEndpoint(kid: String, _ keysEndpoint: String) throws -> [String: String]? {
        guard let url = URL(string: keysEndpoint),
              let keys = try RequestsAPI.getJSON(url)?["keys"] as? [Any] else
              {
                  return nil
              }
        
        return self.findKeyByKeyId(kid: kid, keys)
    }

    /**
     Returns the matching key from a list of objects.
     - parameters:
         - kid: String representation of the kid to find
         - keys: Array of keys to evaluate
     - returns:
     A JSON Web Key dictionary matching the JWTs kid
     */
    open class func findKeyByKeyId(kid: String, _ keys: [Any]) -> [String: String]? {
        for key in keys {
            let keyDict = key as! [String: String]
            guard let dirtyKid = keyDict["kid"] else {
                continue
            }
            if dirtyKid == kid {
                return keyDict
            }
        }

        return nil
    }

    internal class func buildUserAgentString() -> String {
#if os(iOS)
        return "okta-ios-jwt/\(VERSION) iOS/\(UIDevice.current.systemVersion) Device/\(Utils.deviceModel())"
#elseif os(watchOS)
        return "okta-ios-jwt/\(VERSION) watchOS/\(WKInterfaceDevice.current().systemVersion) Device/\(Utils.deviceModel())"
#elseif os(OSX)
        return "okta-ios-jwt/\(VERSION) macOS/\(ProcessInfo.processInfo.operatingSystemVersion) Device/\(Utils.deviceModel())"
#endif
    }


    /**
     Returns the device model used when making API requests
     - returns:
     A String of the device used (iPhone, iPad, Emulator, etc)
    */
    internal class func deviceModel() -> String {
        // Returns the device information
        var system = utsname()
        uname(&system)
        let model = withUnsafePointer(to: &system.machine.0) { ptr in
            return String(cString: ptr)
        }
        return model
    }
}
