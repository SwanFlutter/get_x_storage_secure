import 'dart:convert';
import 'dart:ffi';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'secret_vault.dart';
import 'vault_internals.dart';

const int _secretSchemaMaxAttributes = 32;

const int _opStore = 0;
const int _opLookup = 1;
const int _opClear = 2;

const String _unavailableHint =
    'libsecret needs a running Secret Service. Install libsecret-1.so.0 and '
    'start a keyring daemon (gnome-keyring-daemon, kdewallet, keepassxc); on a '
    'headless system export XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS.';

/// Linux vault backed by `libsecret` and the Secret Service on D-Bus.
///
/// The secret is stored base64-encoded as the password of an item in the default
/// collection, described by a schema with two string attributes, `namespace` and
/// `alias`.
///
/// ## Why not the `*_sync` helpers
/// `secret_password_store_sync()`, `secret_password_lookup_sync()` and
/// `secret_password_clear_sync()` take their attributes as C varargs, which
/// `dart:ffi` cannot call. This backend uses the documented non-variadic
/// `*_v_sync` variants, which accept a `GHashTable`.
///
/// `SECRET_COLLECTION_DEFAULT` is a macro that expands to
/// `_secret_collection_default()`, a symbol libsecret marks internal and hides,
/// so it cannot be reached either. `secret_service_store()` documents a `NULL`
/// collection as "the default collection", which is the same thing.
///
/// libsecret exposes no non-variadic attribute-only search, so [contains]
/// performs a lookup and discards the value.
///
/// Because the Secret Service stores text, the secret travels to the daemon as a
/// base64 [String]; Dart strings are immutable, so that copy cannot be wiped.
class LinuxSecretVault implements SecretVault {
  factory LinuxSecretVault({
    String namespace = kDefaultVaultNamespace,
    int maxSecretBytes = kMaxVaultSecretBytes,
  }) {
    validateNamespace(namespace);
    validateMaxSecretBytes(maxSecretBytes);
    return LinuxSecretVault._(namespace, maxSecretBytes);
  }

  const LinuxSecretVault._(this.namespace, this.maxSecretBytes);

  final String namespace;

  @override
  final int maxSecretBytes;

  @override
  Future<void> write(String alias, Uint8List secret) async {
    validateAlias(alias);
    validateSecret(secret, maxSecretBytes);
    final String text = base64Encode(secret);
    vaultCheckWire(
      'write "$alias"',
      await Isolate.run(() => _execute(namespace, alias, _opStore, text)),
    );
  }

  @override
  Future<Uint8List?> read(String alias) async {
    validateAlias(alias);
    final VaultWire wire = await Isolate.run(
      () => _execute(namespace, alias, _opLookup, null),
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
      await Isolate.run(() => _execute(namespace, alias, _opClear, null)),
    );
  }

  @override
  Future<bool> contains(String alias) async {
    validateAlias(alias);
    final VaultWire wire = await Isolate.run(
      () => _execute(namespace, alias, _opLookup, null),
    );
    if (wire.status == kVaultNotFound) {
      return false;
    }
    vaultCheckWire('check "$alias"', wire);
    return true;
  }
}

/// Loads `libsecret` and `libglib` on first use; Dart initialises top-level
/// finals lazily, so importing this file opens no library.
final _Loaded _loaded = _load();

class _Loaded {
  const _Loaded(this.libSecret, this.failure);

  final _LibSecret? libSecret;
  final VaultWire? failure;
}

_Loaded _load() {
  try {
    return _Loaded(
      _LibSecret(
        DynamicLibrary.open('libsecret-1.so.0'),
        DynamicLibrary.open('libglib-2.0.so.0'),
      ),
      null,
    );
  } on Object catch (error) {
    return _Loaded(
      null,
      vaultUnavailable(
        detail:
            'Could not load libsecret-1.so.0 or libglib-2.0.so.0: $error. '
            '$_unavailableHint',
      ),
    );
  }
}

VaultWire _execute(
  String namespace,
  String alias,
  int operation,
  String? text,
) {
  final _Loaded loaded = _loaded;
  if (loaded.failure != null) {
    return loaded.failure!;
  }
  final _LibSecret libsecret = loaded.libSecret!;
  final Pointer<Pointer<_GError>> probe = calloc<Pointer<_GError>>();
  try {
    // Establishes the D-Bus connection, so a machine without a keyring daemon is
    // reported as unavailable rather than as an operation failure. libsecret
    // keeps the returned service as a process-wide singleton, so the reference
    // taken here is deliberately not dropped.
    if (libsecret.serviceGet(0, nullptr, probe) == nullptr) {
      return _wireFromError(probe, libsecret, unavailable: true);
    }
    final _Op op = _Op(libsecret, namespace, alias);
    try {
      return switch (operation) {
        _opStore => op.store(text!),
        _opLookup => op.lookup(),
        _ => op.clear(),
      };
    } finally {
      op.dispose();
    }
  } finally {
    calloc.free(probe);
  }
}

VaultWire _wireFromError(
  Pointer<Pointer<_GError>> slot,
  _LibSecret libsecret, {
  bool unavailable = false,
}) {
  final Pointer<_GError> raised = slot.value;
  if (raised == nullptr) {
    return unavailable
        ? vaultUnavailable(detail: _unavailableHint)
        : vaultNotFound();
  }
  final int code = raised.ref.code;
  libsecret.errorFree(raised);
  return unavailable
      ? vaultUnavailable(osCode: code, detail: _unavailableHint)
      : vaultFailure(code);
}

/// Holds the schema and attribute table for a single operation.
///
/// `GHashTable` keys and values are copied with `g_strdup`, because the table
/// owns them and releases them with `g_free`, which must never be handed memory
/// allocated by Dart.
class _Op {
  _Op(this._libsecret, this._namespace, this._alias) : _arena = Arena() {
    _schema = _arena<_SecretSchema>()
      ..ref.name = _namespace.toNativeUtf8(allocator: _arena)
      ..ref.flags = 0;
    _setAttribute(0, 'namespace');
    _setAttribute(1, 'alias');

    _table = _libsecret.hashTableNewFull(
      _libsecret.strHash,
      _libsecret.strEqual,
      _libsecret.freeNotify,
      _libsecret.freeNotify,
    );
    _put('namespace', _namespace);
    _put('alias', _alias);
    _label = '$_namespace/$_alias'.toNativeUtf8(allocator: _arena);
  }

  final _LibSecret _libsecret;
  final String _namespace;
  final String _alias;
  final Arena _arena;
  late final Pointer<_SecretSchema> _schema;
  late final Pointer<Opaque> _table;
  late final Pointer<Utf8> _label;

  void _setAttribute(int index, String name) {
    final _SecretSchemaAttribute attribute = _schema.ref.attributes[index];
    attribute.name = name.toNativeUtf8(allocator: _arena);
    // SECRET_SCHEMA_ATTRIBUTE_STRING is zero; assigned for clarity.
    attribute.type = 0;
  }

  void _put(String name, String value) {
    _libsecret.hashTableInsert(
      _table,
      _libsecret.strdup(name.toNativeUtf8(allocator: _arena)).cast<Void>(),
      _libsecret.strdup(value.toNativeUtf8(allocator: _arena)).cast<Void>(),
    );
  }

  VaultWire store(String text) {
    final Pointer<Pointer<_GError>> error = _arena<Pointer<_GError>>();
    final int stored = _libsecret.storev(
      _schema,
      _table,
      nullptr,
      _label,
      text.toNativeUtf8(allocator: _arena),
      nullptr,
      error,
    );
    return stored != 0 ? vaultOk() : _finish(error);
  }

  VaultWire lookup() {
    final Pointer<Pointer<_GError>> error = _arena<Pointer<_GError>>();
    final Pointer<Utf8> found = _libsecret.lookupv(
      _schema,
      _table,
      nullptr,
      error,
    );
    if (found == nullptr) {
      return _finish(error);
    }
    final String text = found.toDartString();
    found.cast<Uint8>().asTypedList(text.length).fillRange(0, text.length, 0);
    _libsecret.passwordFree(found);
    try {
      return vaultOk(base64Decode(text));
    } on FormatException {
      return vaultFailure(-1);
    }
  }

  VaultWire clear() {
    final Pointer<Pointer<_GError>> error = _arena<Pointer<_GError>>();
    // FALSE without an error simply means there was nothing to delete.
    if (_libsecret.clearv(_schema, _table, nullptr, error) != 0) {
      return vaultOk();
    }
    return _finish(error);
  }

  VaultWire _finish(Pointer<Pointer<_GError>> error) =>
      _wireFromError(error, _libsecret);

  void dispose() {
    _libsecret.hashTableUnref(_table);
    _arena.releaseAll();
  }
}

/// `GError`: `quark domain; gint code; gchar *message`.
final class _GError extends Struct {
  @Uint32()
  external int domain;

  @Int32()
  external int code;

  external Pointer<Utf8> message;
}

/// Layout taken from `libsecret/secret-schema.h`: a name, flags, 32 attribute
/// descriptors, then private padding. Unused attribute names stay `NULL`, which
/// is how libsecret finds the end of the schema.
final class _SecretSchema extends Struct {
  external Pointer<Utf8> name;

  @Int32()
  external int flags;

  @Array(_secretSchemaMaxAttributes)
  external Array<_SecretSchemaAttribute> attributes;

  @Int32()
  external int reserved;

  external Pointer<Opaque> reserved1;
  external Pointer<Opaque> reserved2;
  external Pointer<Opaque> reserved3;
  external Pointer<Opaque> reserved4;
  external Pointer<Opaque> reserved5;
  external Pointer<Opaque> reserved6;
  external Pointer<Opaque> reserved7;
}

final class _SecretSchemaAttribute extends Struct {
  external Pointer<Utf8> name;

  @Int32()
  external int type;
}

// GLib calls `gboolean` a widened `gint`, so boolean returns cross as Int32
// rather than as Dart bool.
typedef _GBoolVNative = Int32 Function(
  Pointer<_SecretSchema>,
  Pointer<Opaque>,
  Pointer<Opaque>,
  Pointer<Pointer<_GError>>,
);
typedef _GBoolVDart = int Function(
  Pointer<_SecretSchema>,
  Pointer<Opaque>,
  Pointer<Opaque>,
  Pointer<Pointer<_GError>>,
);
typedef _StorevNative = Int32 Function(
  Pointer<_SecretSchema>,
  Pointer<Opaque>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Opaque>,
  Pointer<Pointer<_GError>>,
);
typedef _StorevDart = int Function(
  Pointer<_SecretSchema>,
  Pointer<Opaque>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Utf8>,
  Pointer<Opaque>,
  Pointer<Pointer<_GError>>,
);
typedef _LookupvNative = Pointer<Utf8> Function(
  Pointer<_SecretSchema>,
  Pointer<Opaque>,
  Pointer<Opaque>,
  Pointer<Pointer<_GError>>,
);
typedef _LookupvDart = Pointer<Utf8> Function(
  Pointer<_SecretSchema>,
  Pointer<Opaque>,
  Pointer<Opaque>,
  Pointer<Pointer<_GError>>,
);
typedef _ServiceGetNative = Pointer<Opaque> Function(
  Uint32,
  Pointer<Opaque>,
  Pointer<Pointer<_GError>>,
);
typedef _ServiceGetDart = Pointer<Opaque> Function(
  int,
  Pointer<Opaque>,
  Pointer<Pointer<_GError>>,
);
typedef _GHashFuncNative = Uint32 Function(Pointer<Void>);
typedef _GEqualFuncNative = Int32 Function(Pointer<Void>, Pointer<Void>);
typedef _GDestroyNotifyNative = Void Function(Pointer<Void>);
typedef _HashTableNewFullNative = Pointer<Opaque> Function(
  Pointer<NativeFunction<_GHashFuncNative>>,
  Pointer<NativeFunction<_GEqualFuncNative>>,
  Pointer<NativeFunction<_GDestroyNotifyNative>>,
  Pointer<NativeFunction<_GDestroyNotifyNative>>,
);
typedef _HashTableNewFullDart = Pointer<Opaque> Function(
  Pointer<NativeFunction<_GHashFuncNative>>,
  Pointer<NativeFunction<_GEqualFuncNative>>,
  Pointer<NativeFunction<_GDestroyNotifyNative>>,
  Pointer<NativeFunction<_GDestroyNotifyNative>>,
);

class _LibSecret {
  _LibSecret(DynamicLibrary libsecret, DynamicLibrary glib)
    : _libsecret = libsecret,
      _glib = glib;

  final DynamicLibrary _libsecret;
  final DynamicLibrary _glib;

  late final _StorevDart storev = _libsecret
      .lookupFunction<_StorevNative, _StorevDart>(
        'secret_password_storev_sync',
      );

  late final _LookupvDart lookupv = _libsecret
      .lookupFunction<_LookupvNative, _LookupvDart>(
        'secret_password_lookupv_sync',
      );

  late final _GBoolVDart clearv = _libsecret
      .lookupFunction<_GBoolVNative, _GBoolVDart>(
        'secret_password_clearv_sync',
      );

  late final void Function(Pointer<Utf8>) passwordFree = _libsecret
      .lookupFunction<
        Void Function(Pointer<Utf8>),
        void Function(Pointer<Utf8>)
      >('secret_password_free');

  late final _ServiceGetDart serviceGet = _libsecret
      .lookupFunction<_ServiceGetNative, _ServiceGetDart>(
        'secret_service_get_sync',
      );

  late final _HashTableNewFullDart hashTableNewFull = _glib
      .lookupFunction<_HashTableNewFullNative, _HashTableNewFullDart>(
        'g_hash_table_new_full',
      );

  late final void Function(Pointer<Opaque>, Pointer<Void>, Pointer<Void>)
  hashTableInsert = _glib
      .lookupFunction<
        Void Function(Pointer<Opaque>, Pointer<Void>, Pointer<Void>),
        void Function(Pointer<Opaque>, Pointer<Void>, Pointer<Void>)
      >('g_hash_table_insert');

  late final void Function(Pointer<Opaque>) hashTableUnref = _glib
      .lookupFunction<
        Void Function(Pointer<Opaque>),
        void Function(Pointer<Opaque>)
      >('g_hash_table_unref');

  late final Pointer<Utf8> Function(Pointer<Utf8>) strdup = _glib
      .lookupFunction<
        Pointer<Utf8> Function(Pointer<Utf8>),
        Pointer<Utf8> Function(Pointer<Utf8>)
      >('g_strdup');

  late final void Function(Pointer<_GError>) errorFree = _glib
      .lookupFunction<
        Void Function(Pointer<_GError>),
        void Function(Pointer<_GError>)
      >('g_error_free');

  late final Pointer<NativeFunction<_GHashFuncNative>> strHash = _glib
      .lookup<NativeFunction<_GHashFuncNative>>('g_str_hash');

  late final Pointer<NativeFunction<_GEqualFuncNative>> strEqual = _glib
      .lookup<NativeFunction<_GEqualFuncNative>>('g_str_equal');

  late final Pointer<NativeFunction<_GDestroyNotifyNative>> freeNotify = _glib
      .lookup<NativeFunction<_GDestroyNotifyNative>>('g_free');
}
