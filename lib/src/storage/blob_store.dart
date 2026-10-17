import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../vault/secret_vault.dart';
import '../vault/vault_internals.dart';

/// Stores byte records of any length in a [SecretVault], which only accepts
/// small ones, by splitting each record into vault-sized parts.
///
/// A record is one metadata entry holding the part size and the total length,
/// plus ceil(length / partSize) parts. Because the metadata is written last, a
/// record that is only half written still reads back as the previous one, and a
/// record whose parts were lost reads back as `null` (and is then purged) rather
/// than as a truncated value.
///
/// Names are arbitrary strings: each one becomes an alias through [sha256], so
/// the vault's `[A-Za-z0-9._-]` rule and its 128-character cap never see the
/// caller's spelling, and two names that differ only in case stay distinct.
class BlobStore {
  BlobStore(this._vault);

  final SecretVault _vault;

  /// Writes [bytes] under [name], replacing whatever was there.
  Future<void> write(String name, Uint8List bytes) async {
    final int partSize = _vault.maxSecretBytes;
    final int partCount = (bytes.length / partSize).ceil();
    final int previousParts = await _readPartCount(name) ?? 0;
    for (int i = 0; i < partCount; i++) {
      final int start = i * partSize;
      final int end = min(start + partSize, bytes.length);
      await _vault.write(
        _partAlias(name, i),
        Uint8List.sublistView(bytes, start, end),
      );
    }
    await _vault.write(_metaAlias(name), _encodeMeta(partSize, bytes.length));
    for (int i = partCount; i < previousParts; i++) {
      await _vault.delete(_partAlias(name, i));
    }
  }

  /// The record stored under [name], or null when it is absent or incomplete.
  Future<Uint8List?> read(String name) async {
    final _Meta? meta = await _readMeta(name);
    if (meta == null) {
      return null;
    }
    final Uint8List record = Uint8List(meta.length);
    int offset = 0;
    while (offset < record.length) {
      final int part = offset ~/ meta.partSize;
      final Uint8List? bytes = await _vault.read(_partAlias(name, part));
      if (bytes == null) {
        // A part went missing under a record that claims it exists: the whole
        // thing is untrustworthy, so drop it and report absence.
        await delete(name);
        zeroSecret(record);
        return null;
      }
      final int end = min(offset + bytes.length, record.length);
      record.setRange(offset, end, bytes);
      zeroSecret(bytes);
      offset = end;
    }
    return record;
  }

  Future<void> delete(String name) async {
    final _Meta? meta = await _readMeta(name);
    final int partCount = meta == null
        ? 1
        : (meta.length / meta.partSize).ceil();
    for (int i = 0; i < partCount; i++) {
      await _vault.delete(_partAlias(name, i));
    }
    await _vault.delete(_metaAlias(name));
  }

  Future<bool> contains(String name) => _vault.contains(_metaAlias(name));

  Future<_Meta?> _readMeta(String name) async {
    final Uint8List? bytes = await _vault.read(_metaAlias(name));
    if (bytes == null) {
      return null;
    }
    final _Meta? meta = _decodeMeta(bytes);
    zeroSecret(bytes);
    return meta;
  }

  Future<int?> _readPartCount(String name) async {
    final _Meta? meta = await _readMeta(name);
    if (meta == null) {
      return null;
    }
    return (meta.length / meta.partSize).ceil();
  }
}

String _metaAlias(String name) => '${_aliasOf(name)}.m';

String _partAlias(String name, int part) => '${_aliasOf(name)}.$part';

/// An alias valid on every backend, whatever the record name looks like.
String _aliasOf(String name) => sha256.convert(utf8.encode(name)).toString();

Uint8List _encodeMeta(int partSize, int length) {
  final ByteData meta = ByteData(1 + 2 * 4);
  meta.setUint8(0, kVaultBlobVersion);
  meta.setUint32(1, partSize, Endian.little);
  meta.setUint32(5, length, Endian.little);
  return meta.buffer.asUint8List();
}

_Meta? _decodeMeta(Uint8List bytes) {
  if (bytes.length != 9 || bytes[0] != kVaultBlobVersion) {
    return null;
  }
  final ByteData data = ByteData.sublistView(bytes);
  final int partSize = data.getUint32(1, Endian.little);
  if (partSize < 1) {
    return null;
  }
  return (partSize: partSize, length: data.getUint32(5, Endian.little));
}

typedef _Meta = ({int partSize, int length});
