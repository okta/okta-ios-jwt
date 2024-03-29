// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

/*
 * Copyright (c) 2021-Present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import PackageDescription

let package = Package(
    name: "OktaJWT",
    platforms: [
        .iOS(.v12),
        .macOS(.v10_14),
        .watchOS(.v6),
    ],
    products: [
        .library(name: "OktaJWT",
                 targets: [
                    "OktaJWT"
                 ]),
    ],
    targets: [
        .target(name: "OktaDataJWT",
                path: "Sources/ThirdParty/JSONWebToken/NSData+Utils",
                publicHeadersPath: "."),
        
        .target(name: "OktaJWT",
                dependencies: [
                    "OktaDataJWT",
                ],
                path: "Sources",
                exclude: [
                    "ThirdParty/JSONWebToken/NSData+Utils",
                    "ThirdParty/JSONWebToken/Info.plist",
                    "ThirdParty/JSONWebToken/LICENCE",
                ]),
    ] + [
        .testTarget(name: "OktaJWTTests",
                    dependencies: [
                        "OktaJWT",
                    ],
                    path: "Tests",
                    exclude: [
                        "iOS/OktaJWTTestSuite",
                    ],
                    resources: [
                        .copy("Resources/TestJWTs.plist"),
                        .copy("Resources/sampleIncorrectJSON.json"),
                        .copy("Resources/sampleCorrectJSON.json"),
                    ])
    ]
)
