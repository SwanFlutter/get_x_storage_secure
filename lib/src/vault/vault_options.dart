import 'vault_internals.dart';

/// Keychain accessibility classes an Apple vault may request.
///
/// The name of each value is the `kSecAttrAccessible…` constant written to the
/// item, so `afterFirstUnlock` maps to `kSecAttrAccessibleAfterFirstUnlock`.
/// Anything a secret must survive a reboot (a token unlocked by a background
/// extension, say) needs `afterFirstUnlock`; `whenUnlocked` is the tightest
/// class and the default.
enum AppleAccessibility {
  whenUnlocked,
  whenUnlockedThisDeviceOnly,
  afterFirstUnlock,
  afterFirstUnlockThisDeviceOnly;

  /// Whether the class keeps the item on the device it was created on, which is
  /// incompatible with iCloud keychain sync.
  bool get isThisDeviceOnly => name.endsWith('ThisDeviceOnly');
}

/// How strongly an Apple item is gated on the user.
enum AppleAuthentication {
  /// No access control: the item is released whenever the accessibility class
  /// allows it.
  none,

  /// `kSecAccessControlUserPresence`: Touch ID, Face ID or the device passcode
  /// each satisfy it.
  userPresence,

  /// `kSecAccessControlBiometryCurrentSet`: only biometrics satisfy it, and
  /// enrolling or removing a fingerprint or face destroys the item.
  biometryCurrentSet;

  /// Whether the item needs the user at all.
  bool get isRequired => this != none;
}

/// Options that only make sense on Android.
class AndroidVaultOptions {
  const AndroidVaultOptions({
    this.requireUserAuthentication = false,
    this.authenticationTimeoutSeconds = kDefaultAuthenticationTimeoutSeconds,
  });

  /// Whether AndroidKeyStore refuses to use its key unless the user
  /// authenticated recently — by unlocking the device or through a biometric
  /// prompt the app shows itself.
  ///
  /// A call made outside that window throws
  /// [VaultAuthenticationRequiredException]; the secret is intact.
  final bool requireUserAuthentication;

  /// How long an authentication stays valid for this key.
  final int authenticationTimeoutSeconds;

  void validate() {
    if (requireUserAuthentication) {
      _validateTimeout(authenticationTimeoutSeconds);
    }
  }
}

/// Options that only make sense on iOS and macOS.
class AppleVaultOptions {
  const AppleVaultOptions({
    this.accessibility = AppleAccessibility.whenUnlockedThisDeviceOnly,
    this.synchronizable = false,
    this.accessGroup,
    this.authentication = AppleAuthentication.none,
    this.authenticationPrompt,
  });

  final AppleAccessibility accessibility;

  /// Whether the item may replicate through the user's iCloud keychain.
  /// Requires a class without the `ThisDeviceOnly` suffix.
  final bool synchronizable;

  /// `kSecAttrAccessGroup`, for apps and extensions that share one vault under
  /// the `keychain-access-groups` entitlement.
  final String? accessGroup;

  /// Whether reading the item makes the system ask the user first.
  final AppleAuthentication authentication;

  /// The message of that system dialog. Localise it in the app: Keychain access
  /// control gives Dart no hook to translate it later.
  final String? authenticationPrompt;

  void validate() {
    if (synchronizable && accessibility.isThisDeviceOnly) {
      throw ArgumentError.value(
        accessibility,
        'apple.accessibility',
        'cannot sync a ThisDeviceOnly item through iCloud',
      );
    }
    final String? group = accessGroup;
    if (group != null) {
      validateAlias(group);
    }
    if (authentication.isRequired && (authenticationPrompt?.isEmpty ?? true)) {
      throw ArgumentError.value(
        authenticationPrompt,
        'apple.authenticationPrompt',
        'a gated item needs the text of the dialog the system will show',
      );
    }
  }
}

/// Options that only make sense on Windows.
class WindowsVaultOptions {
  const WindowsVaultOptions({this.directory});

  /// Where DPAPI blobs are kept. Defaults to
  /// `<%LOCALAPPDATA%>\<namespace>\secure_vault`.
  final String? directory;
}

/// Per-platform knobs for one vault, resolved by `createPlatformVault`.
///
/// A platform ignores the options belonging to another, so the same
/// [VaultOptions] instance can be passed everywhere.
class VaultOptions {
  const VaultOptions({
    this.maxSecretBytes = kMaxVaultSecretBytes,
    this.apple = const AppleVaultOptions(),
    this.android = const AndroidVaultOptions(),
    this.windows = const WindowsVaultOptions(),
  });

  /// Largest secret a single vault write accepts, in bytes.
  final int maxSecretBytes;
  final AppleVaultOptions apple;
  final AndroidVaultOptions android;
  final WindowsVaultOptions windows;

  void validate() {
    validateMaxSecretBytes(maxSecretBytes);
    apple.validate();
    android.validate();
  }
}

/// Window that both gated backends accept, in seconds.
const int kDefaultAuthenticationTimeoutSeconds = 15;

void _validateTimeout(int seconds) {
  if (seconds < 1 || seconds > kMaxAuthenticationTimeoutSeconds) {
    throw ArgumentError.value(
      seconds,
      'authenticationTimeoutSeconds',
      'must be between 1 and $kMaxAuthenticationTimeoutSeconds seconds',
    );
  }
}

/// The longest window AndroidKeyStore documents for a use-again-after-auth
/// key.
const int kMaxAuthenticationTimeoutSeconds = 300;
