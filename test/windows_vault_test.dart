import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/src/vault/secret_vault.dart';
import 'package:get_x_storage_secure/src/vault/vault_internals.dart';
import 'package:get_x_storage_secure/src/vault/windows_vault.dart';

import 'vault_contract.dart';

final bool _onWindows = Platform.isWindows;

void main() {
  late Directory vaultDir;

  setUpAll(() {
    if (_onWindows) {
      vaultDir = Directory.systemTemp.createTempSync('gxs_vault');
    }
  });
  tearDownAll(() {
    if (_onWindows) {
      vaultDir.deleteSync(recursive: true);
    }
  });

  group(
    'WindowsSecretVault contract',
    skip: _onWindows ? false : 'needs Windows',
    () {
      verifySecretVaultContract(
        () =>
            WindowsSecretVault(namespace: 'gxs.test', directory: vaultDir.path),
        aliases: <String>[
          'master_key',
          'rotate.me',
          'presence-check',
          'delete-me',
          'never-written',
          'also-never-written',
          'first.alias',
          'second_alias',
          'oversize-check',
        ],
      );
    },
  );

  group(
    'WindowsSecretVault specifics',
    skip: _onWindows ? false : 'needs Windows',
    () {
      WindowsSecretVault vault() =>
          WindowsSecretVault(namespace: 'gxs.test', directory: vaultDir.path);

      Uint8List secret(int seed) => Uint8List.fromList(
        List<int>.generate(32, (i) => (i * 3 + seed) & 0xff),
      );

      File blobOf(WindowsSecretVault v, String alias) =>
          File('${v.vaultDirectory}\\${vaultFileName(v.namespace, alias)}');

      test('an alias cannot replay another alias\'s blob', () async {
        final WindowsSecretVault v = vault();
        await v.write('alias-a', secret(1));
        blobOf(v, 'alias-a').copySync(blobOf(v, 'alias-b').path);
        // Same user and machine, so only the per-alias entropy distinguishes them.
        expect(await v.read('alias-b'), isNull);
        expect(await v.read('alias-a'), equals(secret(1)));
        await v.delete('alias-a');
        await v.delete('alias-b');
      });

      test('a tampered blob reads as absent, not broken', () async {
        final WindowsSecretVault v = vault();
        await v.write('tamper', secret(2));
        final File blob = blobOf(v, 'tamper');
        final Uint8List bytes = blob.readAsBytesSync();
        bytes[bytes.length - 1] ^= 0xff;
        blob.writeAsBytesSync(bytes, flush: true);
        expect(await v.read('tamper'), isNull);
        await v.delete('tamper');
      });

      test('an unknown framing version throws', () async {
        final WindowsSecretVault v = vault();
        await v.write('version', secret(3));
        final File blob = blobOf(v, 'version');
        final Uint8List bytes = blob.readAsBytesSync();
        bytes[0] = 99;
        blob.writeAsBytesSync(bytes, flush: true);
        await expectLater(
          v.read('version'),
          throwsA(isA<VaultOperationException>()),
        );
        await v.delete('version');
      });

      test('blobs live below the namespace directory by default', () {
        final WindowsSecretVault v = WindowsSecretVault(
          namespace: 'gxs.default',
        );
        expect(v.vaultDirectory, contains('gxs.default'));
        expect(v.vaultDirectory, endsWith('secure_vault'));
      });

      test('a raised cap stores and returns a larger secret', () async {
        final WindowsSecretVault v = WindowsSecretVault(
          namespace: 'gxs.big',
          directory: vaultDir.path,
          maxSecretBytes: 64 * 1024,
        );
        expect(v.maxSecretBytes, 64 * 1024);
        final Uint8List blob = Uint8List.fromList(
          List<int>.generate(40 * 1024, (i) => i & 0xff),
        );
        await v.write('large', blob);
        expect(await v.read('large'), equals(blob));
        await v.delete('large');
        expect(await v.read('large'), isNull);
      });

      test('a cap beyond the ceiling is rejected', () {
        expect(
          () => WindowsSecretVault(
            directory: vaultDir.path,
            maxSecretBytes: kMaxConfigurableVaultSecretBytes + 1,
          ),
          throwsA(isA<ArgumentError>()),
        );
      });
    },
  );
}
