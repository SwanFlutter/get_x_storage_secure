#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint get_x_storage_secure.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'get_x_storage_secure'
  s.version          = '1.0.0'
  s.summary          = 'OS-protected secret storage for Flutter.'
  s.description      = <<-DESC
Keep secrets in the operating system's own store - AndroidKeyStore, DPAPI, the
Keychain, libsecret - with a key/value layer over them.
                       DESC
  s.homepage         = 'https://github.com/SwanFlutter/get_x_storage_secure'
  s.license          = { :file => '../LICENSE' }
  s.author           = 'Swan Flutter'

  # This will ensure the source files in Classes/ are included in the native
  # builds of apps using this FFI plugin. Podspec does not support relative
  # paths, so Classes contains a forwarder C file that relatively imports
  # `../src/*` so that the C sources can be shared among all target platforms.
  s.source           = { :path => '.' }
  s.source_files = 'get_x_storage_secure/Sources/get_x_storage_secure/**/*'

  # If your plugin requires a privacy manifest, for example if it collects user
  # data, update the PrivacyInfo.xcprivacy file to describe your plugin's
  # privacy impact, and then uncomment this line. For more information,
  # see https://developer.apple.com/documentation/bundleresources/privacy_manifest_files
  # s.resource_bundles = {'get_x_storage_secure_privacy' => ['get_x_storage_secure/Sources/get_x_storage_secure/PrivacyInfo.xcprivacy']}

  s.dependency 'FlutterMacOS'

  s.platform = :osx, '10.11'
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES' }
  s.swift_version = '5.0'
end
