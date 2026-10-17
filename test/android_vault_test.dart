import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/src/vault/android_vault.dart';

import 'vault_contract.dart';

/// Needs a real device: `AndroidKeyStore` is absent from the host VM, so the
/// whole group is skipped there. Run it with
/// `flutter test test/android_vault_test.dart -d <device>`.
void main() {
  group(
    'AndroidSecretVault contract',
    skip: Platform.isAndroid ? false : 'needs an Android device',
    () {
      verifySecretVaultContract(
        () => AndroidSecretVault(namespace: 'gxs.test'),
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
}
