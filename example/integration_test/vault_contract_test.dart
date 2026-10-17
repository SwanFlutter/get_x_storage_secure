import 'package:get_x_storage_secure/get_x_storage_secure.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

import '../../test/vault_contract.dart';

/// Runs the shared behavioural contract against whatever vault
/// [createPlatformVault] picks, so one file covers the Android device run and
/// the desktop one.
///
/// `flutter test integration_test -d <device>`
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('platform vault contract', () {
    verifySecretVaultContract(
      createPlatformVault,
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
  });
}
