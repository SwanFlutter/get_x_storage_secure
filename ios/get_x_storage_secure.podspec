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
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '15.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'
end
