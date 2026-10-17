import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/get_x_storage_secure.dart';
import 'package:integration_test/integration_test.dart';

import '../../test/secure_storage_contract.dart';

/// Runs the storage contract against the secret vault of the real operating
/// system, so the chunking, the key index and the hashed aliases are exercised
/// on the facility that actually has to hold them.
///
/// Each instance gets its own namespace: the contract expects a store with no
/// keys, and a namespace shared between runs would inherit the previous one.
///
/// `flutter test integration_test -d <device-or-windows>`
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  final String runTag = 'run${DateTime.now().millisecondsSinceEpoch}';
  final List<SecureStorage> created = <SecureStorage>[];

  group('platform storage contract', () {
    tearDownAll(() async {
      for (final SecureStorage store in created) {
        await store.deleteAll();
        await store.dispose();
      }
    });

    verifySecureStorageContract(() async {
      final SecureStorage store = SecureStorage(
        namespace: '$runTag-${created.length}',
      );
      created.add(store);
      return store;
    });
  });
}
