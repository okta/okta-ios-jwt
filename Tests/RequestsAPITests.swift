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
class RequestsAPITests: XCTestCase {
    
    let correctJSONfileName = "sampleCorrectJSON"
    let incorrectJSONFileName = "sampleIncorrectJSON"

    func testRandomURL() throws {
        let url:URL = URL(string: "hts://dummy.com")!
        XCTAssertNil(RequestsAPI.getJSON(url))
    }
    
    func testCorrectJSONWithWorkingURL() throws {
        let bundle = Bundle(for: type(of: self ))
        guard let url = bundle.url(forResource: correctJSONfileName, withExtension: "json") else {
            fatalError("Failed to locate \(correctJSONfileName) in bundle.")
        }
        XCTAssertTrue(RequestsAPI.getJSON(url) != nil)
    }

    func testIncorrectJSONWithWorkingURL() throws {
        let bundle = Bundle(for: type(of: self ))
        guard let url = bundle.url(forResource: incorrectJSONFileName, withExtension: "json") else {
            fatalError("Failed to locate \(incorrectJSONFileName) in bundle.")
        }
        XCTAssertNil(RequestsAPI.getJSON(url))
    }
}
