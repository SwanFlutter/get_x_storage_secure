import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/src/vault/apple_vault.dart';

import 'vault_contract.dart';

/// Runs only where the Security framework exists; a host without iOS or macOS
/// skips the whole group, so CI without an Apple runner stays green.
void main() {
  final bool onApple = Platform.isIOS || Platform.isMacOS;
  // A per-run namespace keeps concurrent jobs from sharing keychain items.
  final String namespace = 'gxs.test.${DateTime.now().microsecondsSinceEpoch}';

  group(
    'AppleSecretVault contract',
    skip: onApple ? false : 'needs iOS or macOS',
    () {
      verifySecretVaultContract(
        () => AppleSecretVault(namespace: namespace),
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
