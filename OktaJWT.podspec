Pod::Spec.new do |s|
  s.name             = 'OktaJWT'
  s.version          = '0.1.0'
  s.summary          = 'A JWT signing and verification libarary'

  s.description      = <<-DESC
Library to sign and validate JSON Web Tokens.
                       DESC

  s.homepage         = 'https://github.com/okta/okta-ios-jwt'
  s.license          = { :type => 'Apache-2.0', :file => 'LICENSE' }
  s.author           = { 'okta' => 'developers@okta.com' }
  s.source           = { :git => 'https://github.com/okta/okta-ios-jwt.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/oktaDev'

  s.ios.deployment_target = '8.0'

  s.source_files = 'OktaJWT/**/*.{h,m,swift}'
end
