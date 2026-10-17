import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'secret_vault.dart';
import 'vault_internals.dart';
import 'vault_options.dart';

const int _errSecSuccess = 0;
const int _errSecItemNotFound = -25300;
const int _errSecDuplicateItem = -25299;

/// The item exists but the Keychain will not touch it while the device is
/// locked, or while a gated item needs the user.
const int _errSecInteractionNotAllowed = -25308;

/// Touch ID, Face ID or the passcode was refused, or timed out.
const int _errSecAuthFailed = -25293;

/// `SecAccessControlCreateWithFlags` refused the class/flag combination.
const int _errSecParam = -50;

const int _kCFStringEncodingUTF8 = 0x08000100;

/// Both codes above mean the same thing to a caller: the secret is fine, but
/// the user has to authenticate before the item can be read, replaced or
/// removed.
const String _authHint =
    'The Keychain needs the user to authenticate. On iOS the system shows the '
    'dialog itself when a prompt was configured; retry after it succeeds.';

/// `SecAccessControlCreateFlags`, from SecAccessControl.h.
const int _kSecAccessControlUserPresence = 1 << 0;
const int _kSecAccessControlBiometryCurrentSet = 1 << 3;

/// Keychain-backed vault for iOS and macOS.
///
/// Secrets live in `kSecClassGenericPassword` items with
/// `kSecAttrService = namespace` and `kSecAttrAccount = alias`. By default they
/// are marked `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` and explicitly
/// non-synchronizable, so a value never leaves the device it was written to;
/// [AppleVaultOptions] relaxes either of those.
///
/// On macOS `kSecUseDataProtectionKeychain` is set so the modern data-protection
/// keychain is used instead of the legacy file-backed one.
///
/// With [AppleVaultOptions.authentication] set, the item is created through
/// `SecAccessControlCreateWithFlags` and read with `kSecUseOperationPrompt`, so
/// the system asks the user for biometrics or the passcode before it releases
/// the secret. A cancelled prompt or a locked device throws
/// [VaultAuthenticationRequiredException]; the item itself is untouched.
///
/// `errSecInteractionNotAllowed` (-25308, device locked) surfaces as a
/// [VaultOperationException] carrying that code, so callers can retry after
/// unlock instead of mistaking a locked device for a missing secret.
///
/// ## Entitlements
/// None are required: items land in the app's default keychain access group,
/// derived from its application identifier and bundle prefix. Add the
/// `keychain-access-groups` entitlement (and the matching value in the app's
/// entitlements file) only when several apps or extensions must share one
/// vault; then pass that group through [AppleSecretVault.accessGroup] so it is
/// written and read as `kSecAttrAccessGroup`.
class AppleSecretVault implements SecretVault {
  factory AppleSecretVault({
    String namespace = kDefaultVaultNamespace,
    AppleVaultOptions options = const AppleVaultOptions(),
    int maxSecretBytes = kMaxVaultSecretBytes,
  }) {
    validateNamespace(namespace);
    validateMaxSecretBytes(maxSecretBytes);
    options.validate();
    return AppleSecretVault._(namespace, options, maxSecretBytes);
  }

  const AppleSecretVault._(this.namespace, this.options, this.maxSecretBytes);

  final String namespace;
  final AppleVaultOptions options;

  @override
  final int maxSecretBytes;

  /// `kSecAttrAccessGroup` for the items this vault reads and writes.
  String? get accessGroup => options.accessGroup;

  @override
  Future<void> write(String alias, Uint8List secret) async {
    validateAlias(alias);
    validateSecret(secret, maxSecretBytes);
    final AppleVaultOptions target = options;
    final Uint8List copy = Uint8List.fromList(secret);
    final VaultWire wire;
    try {
      wire = await Isolate.run(
        () => _writeSync(namespace, alias, target, copy),
      );
    } finally {
      zeroSecret(copy);
    }
    vaultCheckWire('write "$alias"', wire);
  }

  @override
  Future<Uint8List?> read(String alias) async {
    validateAlias(alias);
    final VaultWire wire = await Isolate.run(
      () => _readSync(namespace, alias, options),
    );
    if (wire.status == kVaultNotFound) {
      return null;
    }
    vaultCheckWire('read "$alias"', wire);
    return wire.data;
  }

  @override
  Future<void> delete(String alias) async {
    validateAlias(alias);
    vaultCheckWire(
      'delete "$alias"',
      await Isolate.run(() => _deleteSync(namespace, alias, options)),
    );
  }

  @override
  Future<bool> contains(String alias) async {
    validateAlias(alias);
    final VaultWire wire = await Isolate.run(
      () => _containsSync(namespace, alias, options),
    );
    if (wire.status == kVaultNotFound) {
      return false;
    }
    vaultCheckWire('check "$alias"', wire);
    return true;
  }
}

VaultWire _writeSync(
  String namespace,
  String alias,
  AppleVaultOptions options,
  Uint8List secret,
) => _withKeychain((_Keychain kc, _CfBag bag) {
  final Pointer<Opaque> value = bag.data(secret);
  final Pointer<Opaque>? control = options.authentication.isRequired
      ? bag.accessControl(options)
      : null;
  if (options.authentication.isRequired && control == null) {
    return vaultFailure(_errSecParam);
  }
  final int status = kc.secItemAdd(
    bag.item(
      namespace,
      alias,
      options.accessGroup,
      extraKeys: <Pointer<Opaque>>[
        kc.symbol('kSecValueData'),
        // An access control object carries its own accessibility class, and the
        // two attributes are mutually exclusive in one item.
        kc.symbol(
          control == null ? 'kSecAttrAccessible' : 'kSecAttrAccessControl',
        ),
        kc.symbol('kSecAttrSynchronizable'),
      ],
      extraValues: <Pointer<Opaque>>[
        value,
        control ??
            kc.symbol(_accessibilityAttributeName(options.accessibility)),
        kc.symbol(
          options.synchronizable ? 'kCFBooleanTrue' : 'kCFBooleanFalse',
        ),
      ],
    ),
    nullptr,
  );
  if (status != _errSecDuplicateItem) {
    return status == _errSecSuccess ? vaultOk() : _failureFrom(status);
  }
  // Replace the payload only: accessibility and synchronizability cannot be
  // changed on an existing item.
  final Pointer<Opaque> update = bag.dict(
    <Pointer<Opaque>>[kc.symbol('kSecValueData')],
    <Pointer<Opaque>>[value],
  );
  final int updateStatus = kc.secItemUpdate(
    bag.item(
      namespace,
      alias,
      options.accessGroup,
      anySynchronizable: options.synchronizable,
      extraKeys: <Pointer<Opaque>>[
        if (control != null) kc.symbol('kSecUseOperationPrompt'),
      ],
      extraValues: <Pointer<Opaque>>[
        if (control != null) bag.string(options.authenticationPrompt!),
      ],
    ),
    update,
  );
  return updateStatus == _errSecSuccess
      ? vaultOk()
      : _failureFrom(updateStatus);
});

VaultWire _readSync(
  String namespace,
  String alias,
  AppleVaultOptions options,
) => _withKeychain((_Keychain kc, _CfBag bag) {
  final Pointer<Pointer<Opaque>> result = bag.arena<Pointer<Opaque>>();
  final int status = kc.secItemCopyMatching(
    bag.item(
      namespace,
      alias,
      options.accessGroup,
      anySynchronizable: options.synchronizable,
      extraKeys: <Pointer<Opaque>>[
        kc.symbol('kSecReturnData'),
        kc.symbol('kSecMatchLimit'),
        if (options.authentication.isRequired)
          kc.symbol('kSecUseOperationPrompt'),
      ],
      extraValues: <Pointer<Opaque>>[
        kc.symbol('kCFBooleanTrue'),
        kc.symbol('kSecMatchLimitOne'),
        if (options.authentication.isRequired)
          bag.string(options.authenticationPrompt!),
      ],
    ),
    result,
  );
  if (status == _errSecItemNotFound) {
    return vaultNotFound();
  }
  if (status != _errSecSuccess) {
    return _failureFrom(status);
  }
  final Uint8List secret = kc.cfDataBytes(result.value);
  kc.cfRelease(result.value);
  return vaultOk(secret);
});

VaultWire _deleteSync(
  String namespace,
  String alias,
  AppleVaultOptions options,
) => _withKeychain((_Keychain kc, _CfBag bag) {
  final int status = kc.secItemDelete(
    bag.item(
      namespace,
      alias,
      options.accessGroup,
      anySynchronizable: options.synchronizable,
    ),
  );
  if (status == _errSecItemNotFound) {
    return vaultOk();
  }
  return status == _errSecSuccess ? vaultOk() : _failureFrom(status);
});

VaultWire _containsSync(
  String namespace,
  String alias,
  AppleVaultOptions options,
) => _withKeychain((_Keychain kc, _CfBag bag) {
  final int status = kc.secItemCopyMatching(
    bag.item(
      namespace,
      alias,
      options.accessGroup,
      anySynchronizable: options.synchronizable,
    ),
    nullptr,
  );
  if (status == _errSecItemNotFound) {
    return vaultNotFound();
  }
  return status == _errSecSuccess ? vaultOk() : _failureFrom(status);
});

/// `SecAccessControlCreateFlags` for one gate.
int _accessControlFlags(AppleAuthentication authentication) =>
    switch (authentication) {
      AppleAuthentication.none => 0,
      AppleAuthentication.userPresence => _kSecAccessControlUserPresence,
      AppleAuthentication.biometryCurrentSet =>
        _kSecAccessControlBiometryCurrentSet,
    };

/// Reports the two statuses that mean "the user must authenticate" as
/// [kVaultAuthRequired], so a locked device or a cancelled prompt is not
/// mistaken for a broken secret.
VaultWire _failureFrom(int status) => switch (status) {
  _errSecInteractionNotAllowed ||
  _errSecAuthFailed => vaultAuthRequired(osCode: status, detail: _authHint),
  _ => vaultFailure(status),
};

/// The `kSecAttrAccessible…` constant naming an accessibility class.
String _accessibilityAttributeName(AppleAccessibility accessibility) =>
    switch (accessibility) {
      AppleAccessibility.whenUnlocked => 'kSecAttrAccessibleWhenUnlocked',
      AppleAccessibility.whenUnlockedThisDeviceOnly =>
        'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
      AppleAccessibility.afterFirstUnlock =>
        'kSecAttrAccessibleAfterFirstUnlock',
      AppleAccessibility.afterFirstUnlockThisDeviceOnly =>
        'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
    };

VaultWire _withKeychain(VaultWire Function(_Keychain kc, _CfBag bag) body) {
  final _Keychain kc = _keychain;
  final _CfBag bag = _CfBag(kc);
  try {
    return body(kc, bag);
  } finally {
    bag.dispose();
  }
}

/// Lazily created per isolate: a top-level `final` with an initialiser runs on
/// first read, not on import, and each isolate gets its own handle.
final _Keychain _keychain = _Keychain();

class _Keychain {
  _Keychain()
    : _security = _open('Security'),
      _coreFoundation = _open('CoreFoundation'),
      isMacOS = Platform.isMacOS;

  final DynamicLibrary _security;
  final DynamicLibrary _coreFoundation;
  final bool isMacOS;

  final Map<String, Pointer<Opaque>> _symbols = <String, Pointer<Opaque>>{};

  /// `CFStringRef`, `SecClass` and `CFBooleanRef` constants are exported as
  /// pointer *variables*, so the object reference is the value they point at.
  /// `Sec*` names live in Security, `kCF*` names in CoreFoundation.
  Pointer<Opaque> symbol(String name) => _symbols.putIfAbsent(name, () {
    for (final DynamicLibrary library in <DynamicLibrary>[
      _security,
      _coreFoundation,
    ]) {
      try {
        return library.lookup<Pointer<Opaque>>(name).value;
      } on ArgumentError {
        continue;
      }
    }
    throw VaultUnavailableException(
      'The Keychain symbol $name is not available on this OS version.',
    );
  });

  late final int Function(Pointer<Opaque>, Pointer<Pointer<Opaque>>)
  secItemAdd = _security
      .lookupFunction<
        Int32 Function(Pointer<Opaque>, Pointer<Pointer<Opaque>>),
        int Function(Pointer<Opaque>, Pointer<Pointer<Opaque>>)
      >('SecItemAdd');

  late final int Function(Pointer<Opaque>, Pointer<Pointer<Opaque>>)
  secItemCopyMatching = _security
      .lookupFunction<
        Int32 Function(Pointer<Opaque>, Pointer<Pointer<Opaque>>),
        int Function(Pointer<Opaque>, Pointer<Pointer<Opaque>>)
      >('SecItemCopyMatching');

  late final int Function(Pointer<Opaque>, Pointer<Opaque>) secItemUpdate =
      _security.lookupFunction<
        Int32 Function(Pointer<Opaque>, Pointer<Opaque>),
        int Function(Pointer<Opaque>, Pointer<Opaque>)
      >('SecItemUpdate');

  late final int Function(Pointer<Opaque>) secItemDelete = _security
      .lookupFunction<
        Int32 Function(Pointer<Opaque>),
        int Function(Pointer<Opaque>)
      >('SecItemDelete');

  /// `SecAccessControlCreateWithFlags(allocator, protection, flags, error)`.
  ///
  /// `SecAccessControlCreateFlags` is an `NS_OPTIONS` over `NSUInteger`, so the
  /// flags travel as 64 bits. The error out-parameter is left unread: a null
  /// return already says the class and flags were refused together.
  late final Pointer<Opaque> Function(
    Pointer<Void>,
    Pointer<Opaque>,
    int,
    Pointer<Pointer<Opaque>>,
  )
  secAccessControlCreateWithFlags = _security
      .lookupFunction<
        Pointer<Opaque> Function(
          Pointer<Void>,
          Pointer<Opaque>,
          Uint64,
          Pointer<Pointer<Opaque>>,
        ),
        Pointer<Opaque> Function(
          Pointer<Void>,
          Pointer<Opaque>,
          int,
          Pointer<Pointer<Opaque>>,
        )
      >('SecAccessControlCreateWithFlags');

  late final Pointer<Opaque> Function(Pointer<Opaque>, Pointer<Uint8>, int)
  _cfDataCreate = _coreFoundation
      .lookupFunction<
        Pointer<Opaque> Function(Pointer<Opaque>, Pointer<Uint8>, IntPtr),
        Pointer<Opaque> Function(Pointer<Opaque>, Pointer<Uint8>, int)
      >('CFDataCreate');

  late final Pointer<Uint8> Function(Pointer<Opaque>) _cfDataGetBytePtr =
      _coreFoundation.lookupFunction<
        Pointer<Uint8> Function(Pointer<Opaque>),
        Pointer<Uint8> Function(Pointer<Opaque>)
      >('CFDataGetBytePtr');

  late final int Function(Pointer<Opaque>) _cfDataGetLength = _coreFoundation
      .lookupFunction<
        IntPtr Function(Pointer<Opaque>),
        int Function(Pointer<Opaque>)
      >('CFDataGetLength');

  late final Pointer<Opaque> Function(Pointer<Opaque>, Pointer<Char>, int)
  _cfStringCreateWithCString = _coreFoundation
      .lookupFunction<
        Pointer<Opaque> Function(Pointer<Opaque>, Pointer<Char>, Uint32),
        Pointer<Opaque> Function(Pointer<Opaque>, Pointer<Char>, int)
      >('CFStringCreateWithCString');

  late final Pointer<Opaque> Function(
    Pointer<Opaque>,
    Pointer<Pointer<Void>>,
    Pointer<Pointer<Void>>,
    int,
    Pointer<Void>,
    Pointer<Void>,
  )
  _cfDictionaryCreate = _coreFoundation
      .lookupFunction<
        Pointer<Opaque> Function(
          Pointer<Opaque>,
          Pointer<Pointer<Void>>,
          Pointer<Pointer<Void>>,
          IntPtr,
          Pointer<Void>,
          Pointer<Void>,
        ),
        Pointer<Opaque> Function(
          Pointer<Opaque>,
          Pointer<Pointer<Void>>,
          Pointer<Pointer<Void>>,
          int,
          Pointer<Void>,
          Pointer<Void>,
        )
      >('CFDictionaryCreate');

  late final void Function(Pointer<Opaque>) cfRelease = _coreFoundation
      .lookupFunction<
        Void Function(Pointer<Opaque>),
        void Function(Pointer<Opaque>)
      >('CFRelease');

  Pointer<Opaque> cfString(String value, Allocator arena) =>
      _cfStringCreateWithCString(
        nullptr,
        value.toNativeUtf8(allocator: arena).cast<Char>(),
        _kCFStringEncodingUTF8,
      );

  Pointer<Opaque> cfData(List<int> bytes, Allocator arena) {
    final Pointer<Uint8> buffer = arena<Uint8>(bytes.length);
    buffer.asTypedList(bytes.length).setAll(0, bytes);
    return _cfDataCreate(nullptr, buffer, bytes.length);
  }

  /// Copies a `CFDataRef` into Dart, wiping the native buffer beforehand.
  Uint8List cfDataBytes(Pointer<Opaque> data) {
    final int length = _cfDataGetLength(data);
    final Pointer<Uint8> bytes = _cfDataGetBytePtr(data);
    final Uint8List copy = Uint8List.fromList(bytes.asTypedList(length));
    if (length > 0) {
      bytes.asTypedList(length).fillRange(0, length, 0);
    }
    return copy;
  }

  Pointer<Opaque> createDictionary(
    List<Pointer<Opaque>> keys,
    List<Pointer<Opaque>> values,
    Allocator arena,
  ) => _cfDictionaryCreate(
    nullptr,
    _voidArray(keys, arena),
    _voidArray(values, arena),
    keys.length,
    _callbacks('kCFTypeDictionaryKeyCallBacks'),
    _callbacks('kCFTypeDictionaryValueCallBacks'),
  );

  Pointer<Void> _callbacks(String name) =>
      _coreFoundation.lookup<Opaque>(name).cast<Void>();

  Pointer<Pointer<Void>> _voidArray(
    List<Pointer<Opaque>> items,
    Allocator arena,
  ) {
    final Pointer<Pointer<Void>> array = arena<Pointer<Void>>(items.length);
    for (int i = 0; i < items.length; i++) {
      (array + i).value = items[i].cast<Void>();
    }
    return array;
  }
}

/// Owns every CoreFoundation object created by one vault call so that no
/// `CFRelease` can be skipped on an early return.
class _CfBag {
  _CfBag(this._kc) : _arena = Arena();

  final _Keychain _kc;
  final Arena _arena;
  final List<Pointer<Opaque>> _owned = <Pointer<Opaque>>[];

  Allocator get arena => _arena;

  Pointer<Opaque> data(List<int> bytes) => _track(_kc.cfData(bytes, _arena));

  Pointer<Opaque> dict(
    List<Pointer<Opaque>> keys,
    List<Pointer<Opaque>> values,
  ) => _track(_kc.createDictionary(keys, values, _arena));

  /// The generic-password item named by [namespace] and [alias].
  ///
  /// [extraKeys] and [extraValues] are appended in step, so the two arrays
  /// cannot drift apart.
  ///
  /// [anySynchronizable] matches local and iCloud-replicated items alike, which
  /// a query needs once the vault writes synchronizable ones.
  Pointer<Opaque> item(
    String namespace,
    String alias,
    String? accessGroup, {
    bool anySynchronizable = false,
    List<Pointer<Opaque>> extraKeys = const <Pointer<Opaque>>[],
    List<Pointer<Opaque>> extraValues = const <Pointer<Opaque>>[],
  }) {
    final List<Pointer<Opaque>> keys = <Pointer<Opaque>>[
      _kc.symbol('kSecClass'),
      _kc.symbol('kSecAttrService'),
      _kc.symbol('kSecAttrAccount'),
      if (accessGroup != null) _kc.symbol('kSecAttrAccessGroup'),
      if (_kc.isMacOS) _kc.symbol('kSecUseDataProtectionKeychain'),
      if (anySynchronizable) _kc.symbol('kSecAttrSynchronizable'),
      ...extraKeys,
    ];
    final List<Pointer<Opaque>> values = <Pointer<Opaque>>[
      _kc.symbol('kSecClassGenericPassword'),
      _string(namespace),
      _string(alias),
      if (accessGroup != null) _string(accessGroup),
      if (_kc.isMacOS) _kc.symbol('kCFBooleanTrue'),
      if (anySynchronizable) _kc.symbol('kSecAttrSynchronizableAny'),
      ...extraValues,
    ];
    assert(keys.length == values.length);
    return dict(keys, values);
  }

  /// A `CFStringRef` the bag releases, for values the caller supplies as text.
  Pointer<Opaque> string(String value) => _track(_kc.cfString(value, _arena));

  /// The `SecAccessControlRef` that gates an item on [AppleVaultOptions], or
  /// null when the OS refuses the accessibility class and flag together.
  Pointer<Opaque>? accessControl(AppleVaultOptions options) {
    final Pointer<Opaque> control = _kc.secAccessControlCreateWithFlags(
      nullptr,
      _kc.symbol(_accessibilityAttributeName(options.accessibility)),
      _accessControlFlags(options.authentication),
      nullptr,
    );
    return control == nullptr ? null : _track(control);
  }

  Pointer<Opaque> _string(String value) => string(value);

  Pointer<Opaque> _track(Pointer<Opaque> object) {
    _owned.add(object);
    return object;
  }

  void dispose() {
    for (final Pointer<Opaque> object in _owned.reversed) {
      _kc.cfRelease(object);
    }
    _owned.clear();
    _arena.releaseAll();
  }
}

DynamicLibrary _open(String framework) {
  final String path =
      '/System/Library/Frameworks/$framework.framework/$framework';
  try {
    return DynamicLibrary.open(path);
  } on ArgumentError {
    // Already linked into the running process.
    return DynamicLibrary.process();
  }
}
