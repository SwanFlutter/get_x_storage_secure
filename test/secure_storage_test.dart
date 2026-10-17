import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/get_x_storage_secure.dart';
import 'package:get_x_storage_secure/src/vault/windows_vault.dart';

import 'memory_vault.dart';
import 'secure_storage_contract.dart';

final bool _onWindows = Platform.isWindows;

void main() {
  group('SecureStorage over a memory vault', () {
    // A cap this small forces almost every record through the split path.
    MemorySecretVault backing() => MemorySecretVault(maxSecretBytes: 64);

    verifySecureStorageContract(() async => SecureStorage.fromVault(backing()));

    test('a long value occupies several vault entries', () async {
      final MemorySecretVault vault = backing();
      final SecureStorage store = SecureStorage.fromVault(vault);
      await store.write('long', 'x' * 300);
      // The value is 301 framed bytes, so five 64-byte parts plus its metadata;
      // the key index of eight characters adds one part and its metadata.
      expect(vault.entries.length, 8);
      expect(
        vault.entries.values.every(
          (Uint8List part) => part.length <= vault.maxSecretBytes,
        ),
        isTrue,
      );
      expect(await store.read('long'), 'x' * 300);
    });

    test('a missing part reads back as absent and purges the record', () async {
      final MemorySecretVault vault = backing();
      final SecureStorage store = SecureStorage.fromVault(vault);
      await store.write('long', 'x' * 300);
      final String victim = vault.entries.keys
          .where((String alias) => alias.endsWith('.1'))
          .first;
      await vault.delete(victim);
      expect(await store.read('long'), isNull);
      // The failed read removed the record, its metadata and surviving parts.
      expect(await store.containsKey('long'), isFalse);
    });
  });

  group('SecureStorage over the Windows vault', () {
    late Directory root;
    int instance = 0;

    setUp(() {
      if (_onWindows) {
        root = Directory.systemTemp.createTempSync('gxs_storage');
      }
    });
    tearDown(() {
      if (_onWindows) {
        root.deleteSync(recursive: true);
      }
    });

    SecureStorage over(String directory) => SecureStorage.fromVault(
      WindowsSecretVault(
        namespace: 'gxs.storage',
        directory: directory,
        maxSecretBytes: 128,
      ),
    );

    // One directory per instance, so contract cases cannot see each other.
    SecureStorage create() => over('${root.path}\\v${++instance}');

    verifySecureStorageContract(() async => create());

    test(
      'a second store over the same directory reads what the first wrote',
      () async {
        final SecureStorage first = over(root.path);
        await first.write('session', 'abc123');
        await first.writeBytes(
          'keyfile',
          Uint8List.fromList(<int>[0, 1, 2, 250, 255]),
        );

        final SecureStorage second = over(root.path);
        expect(await second.read('session'), 'abc123');
        expect(await second.readBytes('keyfile'), <int>[0, 1, 2, 250, 255]);
        expect(await second.getKeys(), <String>['session', 'keyfile']);
      },
    );

    test('values are never stored as plaintext', () async {
      final SecureStorage store = create();
      const String marker = 'correct-horse-battery-staple';
      await store.write('token', marker);
      final List<File> blobs = Directory(root.path)
          .listSync(recursive: true)
          .whereType<File>()
          .toList();
      expect(blobs, isNotEmpty);
      for (final File blob in blobs) {
        expect(
          String.fromCharCodes(blob.readAsBytesSync()),
          isNot(contains(marker)),
          reason: '${blob.path} holds the value in the clear',
        );
      }
    });
  });
}
