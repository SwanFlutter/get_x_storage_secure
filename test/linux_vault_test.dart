import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/src/vault/linux_vault.dart';
import 'package:get_x_storage_secure/src/vault/secret_vault.dart';

import 'vault_contract.dart';

/// Needs libsecret *and* a running Secret Service, which CI images and headless
/// machines usually lack, so it stays opt-in:
///
///     GXS_TEST_LIBSECRET=1 flutter test test/linux_vault.dart
void main() {
  final bool enabled =
      Platform.isLinux && Platform.environment['GXS_TEST_LIBSECRET'] == '1';
  final String namespace = 'gxs.test.${DateTime.now().microsecondsSinceEpoch}';

  group(
    'LinuxSecretVault contract',
    skip: enabled ? false : 'needs Linux with a Secret Service',
    () {
      verifySecretVaultContract(
        () => LinuxSecretVault(namespace: namespace),
        aliases: const <String>[
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

  test(
    'reports an actionable error when no Secret Service answers',
    () async {
      final LinuxSecretVault vault = LinuxSecretVault(
        namespace: 'gxs.unavailable',
      );
      await expectLater(
        vault.write('probe', Uint8List(32)),
        throwsA(
          isA<VaultUnavailableException>().having(
            (VaultUnavailableException e) => e.message,
            'message',
            contains('Secret Service'),
          ),
        ),
      );
    },
    skip: Platform.isLinux && !enabled
        ? 'only runs on Linux without a keyring'
        : true,
  );
}
