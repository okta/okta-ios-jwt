Pod::Spec.new do |s|
  s.name             = 'OktaJWT'
  s.version          = '2.3.4'
  s.summary          = 'A JWT verification library'

  s.description      = <<-DESC
Library to validate JSON Web Tokens.
                       DESC
  s.platforms        = { :ios => "12.0", :watchos => "6.0", :osx => "10.14"}
  s.homepage         = 'https://github.com/okta/okta-ios-jwt'
  s.license          = { :type => 'Apache-2.0', :file => 'LICENSE' }
  s.author           = { 'Okta Developers' => 'developers@okta.com' }
  s.source           = { :git => 'https://github.com/okta/okta-ios-jwt.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/oktaDev'

  s.ios.deployment_target = '12.0'
  s.watchos.deployment_target = '6.0'
  s.osx.deployment_target = '10.14'

  s.source_files = 'Sources/**/*.{h,m,swift}'
  s.ios.exclude_files = 'Sources/**/macOS/**'
  s.watchos.exclude_files = 'Sources/**/macOS/**'
  s.osx.exclude_files = 'Sources/**/iOS/**'
  s.swift_version = '5.0'
end
