#
# Be sure to run `pod lib lint DMSOpenPGP.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'DMSOpenPGP'
  s.version          = '0.1.4'
  s.summary          = 'Swift wrapper for Bouncy Castle OpenPGP.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
Swift wrapper for Bouncy Castle OpenPGP. Supports PGP keygen, encrypt & sign, decrypt & verify.
                       DESC

  s.homepage         = 'https://github.com/DimensionDev/DMSOpenPGP'
  s.license          = { :type => 'AGPL', :file => 'LICENSE' }
  s.author           = { 'CMK' => 'cirno.mainasuk@gmail.com' }
  s.source           = { :git => 'https://github.com/DimensionDev/DMSOpenPGP.git', :tag => s.version.to_s }
  s.swift_version    = '5.0'

  s.ios.deployment_target = '11.0'
  s.requires_arc = false

  s.source_files = 'DMSOpenPGP/Classes/**/*'
  s.test_spec 'Tests' do |test_spec|
    test_spec.source_files = 'DMSOpenPGP/Tests/**/*'
    test_spec.dependency 'ConsolePrint'
  end

  s.xcconfig = { 
    'LIBRARY_SEARCH_PATHS' => '"${PODS_ROOT}/BouncyCastle-ObjC/dist/lib"',
    'HEADER_SEARCH_PATHS' => '"${PODS_ROOT}/BouncyCastle-ObjC/dist/frameworks/JRE.framework/Headers"',
  }
  
  # s.resource_bundles = {
  #   'DMSOpenPGP' => ['DMSOpenPGP/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'
  # s.frameworks = 'UIKit', 'MapKit'
  s.dependency 'BouncyCastle-ObjC', '~> 0.1.0'
  s.dependency 'OpenSSL-Universal', '~> 1.0.2.17'

  s.static_framework = true
end
