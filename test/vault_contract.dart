import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/src/vault/secret_vault.dart';

/// One set of expectations every backend must satisfy.
///
/// [create] must return a vault whose aliases are free, so runs do not inherit
/// state from previous ones.
void verifySecretVaultContract(
  SecretVault Function() create, {
  required List<String> aliases,
}) {
  Uint8List key(int seed) =>
      Uint8List.fromList(List<int>.generate(32, (i) => (i + seed) & 0xff));

  test('writes and reads back the same bytes', () async {
    final SecretVault vault = create();
    final Uint8List secret = key(1);
    await vault.write(aliases[0], secret);
    expect(await vault.read(aliases[0]), equals(secret));
    await vault.delete(aliases[0]);
  });

  test('overwrites an existing alias', () async {
    final SecretVault vault = create();
    await vault.write(aliases[1], key(2));
    await vault.write(aliases[1], key(3));
    expect(await vault.read(aliases[1]), equals(key(3)));
    await vault.delete(aliases[1]);
  });

  test('reports presence and absence', () async {
    final SecretVault vault = create();
    expect(await vault.contains(aliases[2]), isFalse);
    await vault.write(aliases[2], key(4));
    expect(await vault.contains(aliases[2]), isTrue);
    await vault.delete(aliases[2]);
  });

  test('deletes an alias', () async {
    final SecretVault vault = create();
    await vault.write(aliases[3], key(5));
    await vault.delete(aliases[3]);
    expect(await vault.contains(aliases[3]), isFalse);
    expect(await vault.read(aliases[3]), isNull);
  });

  test('reading a missing alias returns null instead of throwing', () async {
    final SecretVault vault = create();
    expect(await vault.read(aliases[4]), isNull);
  });

  test('deleting a missing alias is a no-op', () async {
    final SecretVault vault = create();
    await expectLater(vault.delete(aliases[5]), completes);
  });

  test('two aliases in one namespace hold independent secrets', () async {
    final SecretVault vault = create();
    await vault.write(aliases[6], key(8));
    await vault.write(aliases[7], key(9));
    expect(await vault.read(aliases[6]), equals(key(8)));
    expect(await vault.read(aliases[7]), equals(key(9)));
    await vault.delete(aliases[6]);
    expect(await vault.read(aliases[7]), equals(key(9)));
    await vault.delete(aliases[7]);
  });

  test('rejects invalid aliases', () async {
    final SecretVault vault = create();
    for (final String bad in <String>[
      '',
      'has space',
      'slash/alias',
      'dollar\$ign',
      'a' * 129,
    ]) {
      await expectLater(
        vault.write(bad, key(6)),
        throwsA(isA<ArgumentError>()),
        reason: 'alias "$bad" must be rejected',
      );
      await expectLater(
        vault.read(bad),
        throwsA(isA<ArgumentError>()),
        reason: 'alias "$bad" must be rejected',
      );
    }
  });

  test('accepts an alias at the length limit', () async {
    final SecretVault vault = create();
    await expectLater(vault.write('a' * 128, key(7)), completes);
    await vault.delete('a' * 128);
  });

  test('rejects oversized and empty secrets', () async {
    final SecretVault vault = create();
    await expectLater(
      vault.write(aliases[8], Uint8List(0)),
      throwsA(isA<ArgumentError>()),
    );
    await expectLater(
      vault.write(aliases[8], Uint8List(vault.maxSecretBytes + 1)),
      throwsA(isA<ArgumentError>()),
    );
  });

  test('exception text carries a code but no payload', () {
    const VaultOperationException failure = VaultOperationException(
      'Secure storage failed to write.',
      osCode: -12345,
    );
    expect(failure.toString(), contains('-12345'));
    expect(failure.toString(), isNot(contains('correct horse battery staple')));

    const VaultUnavailableException unavailable = VaultUnavailableException(
      'Secure storage is unavailable.',
      osCode: 7,
    );
    expect(unavailable.toString(), contains('7'));
    expect(
      unavailable.toString(),
      isNot(contains('correct horse battery staple')),
    );
  });
}
