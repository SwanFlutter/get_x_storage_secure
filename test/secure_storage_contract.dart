import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/get_x_storage_secure.dart';

/// One set of expectations every [SecureStorage] must satisfy, whatever is
/// underneath it.
///
/// [create] must return a store with no keys, so runs do not inherit state from
/// previous ones. It is asynchronous because emptying a real store on a device
/// takes a round trip through the vault.
void verifySecureStorageContract(Future<SecureStorage> Function() create) {
  Uint8List bytes(int seed, int length) => Uint8List.fromList(
    List<int>.generate(length, (i) => (i * 31 + seed) & 0xff),
  );

  test('stores and returns text', () async {
    final SecureStorage store = await create();
    await store.write('token', 'hunter2');
    expect(await store.read('token'), 'hunter2');
    expect(await store.containsKey('token'), isTrue);
  });

  test('overwrites a key without duplicating it', () async {
    final SecureStorage store = await create();
    await store.write('token', 'first');
    await store.write('token', 'second');
    expect(await store.read('token'), 'second');
    expect(await store.getKeys(), <String>['token']);
  });

  test('keeps non-ASCII keys and values', () async {
    final SecureStorage store = await create();
    const String key = 'توکن کاربر 🚀';
    await store.write(key, 'کلید با حروف فارسی و انگلیسی');
    expect(await store.read(key), 'کلید با حروف فارسی و انگلیسی');
    expect(await store.getKeys(), <String>[key]);
  });

  test('treats keys that differ only in case as different keys', () async {
    final SecureStorage store = await create();
    await store.write('Token', 'capital');
    await store.write('token', 'lower');
    expect(await store.read('Token'), 'capital');
    expect(await store.read('token'), 'lower');
    expect((await store.getKeys()).toSet(), <String>{'Token', 'token'});
  });

  test(
    'accepts a key with no vault-friendly characters and any length',
    () async {
      final SecureStorage store = await create();
      final String key = 'a key/with "stuff": ${'x' * 200}';
      await store.write(key, 'value');
      expect(await store.read(key), 'value');
    },
  );

  test('reads back null for a key that never existed', () async {
    final SecureStorage store = await create();
    expect(await store.read('absent'), isNull);
    expect(await store.readBytes('absent'), isNull);
    expect(await store.containsKey('absent'), isFalse);
  });

  test('deleting a missing key is a no-op', () async {
    final SecureStorage store = await create();
    await expectLater(store.delete('absent'), completes);
  });

  test('an empty value is still a value', () async {
    final SecureStorage store = await create();
    await store.write('empty', '');
    expect(await store.read('empty'), '');
    expect(await store.containsKey('empty'), isTrue);
    expect(await store.getKeys(), <String>['empty']);
  });

  test('rejects an empty key', () async {
    final SecureStorage store = await create();
    await expectLater(store.write('', 'v'), throwsA(isA<ArgumentError>()));
    await expectLater(store.read(''), throwsA(isA<ArgumentError>()));
    await expectLater(store.delete(''), throwsA(isA<ArgumentError>()));
    await expectLater(store.containsKey(''), throwsA(isA<ArgumentError>()));
  });

  test('stores a value larger than one vault write', () async {
    final SecureStorage store = await create();
    // Several vault-sized parts, so the split and reassembly are exercised.
    final String big = 'a' * (store.maxSecretBytes * 3 + 17);
    await store.write('big', big);
    expect(await store.read('big'), big);
    expect(await store.containsKey('big'), isTrue);
  });

  test('stores and returns raw bytes', () async {
    final SecureStorage store = await create();
    final Uint8List value = bytes(4, store.maxSecretBytes + 5);
    await store.writeBytes('blob', value);
    expect(await store.readBytes('blob'), equals(value));
  });

  test('lists and returns everything it holds', () async {
    final SecureStorage store = await create();
    await store.write('one', '1');
    await store.write('two', '2');
    await store.write('three', '3');
    expect(await store.getKeys(), <String>['one', 'two', 'three']);
    expect(await store.readAll(), <String, String>{
      'one': '1',
      'two': '2',
      'three': '3',
    });
  });

  test('deleteAll removes every value', () async {
    final SecureStorage store = await create();
    await store.write('one', '1');
    await store.write('two', '2');
    await store.deleteAll();
    expect(await store.getKeys(), isEmpty);
    expect(await store.readAll(), isEmpty);
    expect(await store.read('one'), isNull);
    expect(await store.containsKey('one'), isFalse);
  });

  test('a key removed from the index can be written again', () async {
    final SecureStorage store = await create();
    await store.write('cycle', 'first');
    await store.delete('cycle');
    await store.write('cycle', 'second');
    expect(await store.getKeys(), <String>['cycle']);
    expect(await store.read('cycle'), 'second');
  });

  test('concurrent writes all survive', () async {
    final SecureStorage store = await create();
    await Future.wait(
      List<Future<void>>.generate(20, (i) => store.write('k$i', '$i')),
    );
    expect((await store.getKeys()).toSet().length, 20);
    expect(await store.read('k7'), '7');
  });

  test('announces writes and deletes', () async {
    final SecureStorage store = await create();
    final List<String> log = <String>[];
    final StreamSubscription<SecureStorageChange> sub = store.changes.listen(
      (SecureStorageChange change) =>
          log.add('${change.key}:${change.kind.name}'),
    );
    await store.write('announced', 'v');
    await store.delete('announced');
    await Future<void>.delayed(Duration.zero);
    expect(log, <String>['announced:written', 'announced:deleted']);
    await sub.cancel();
  });

  test('names the change, never the value', () {
    const SecureStorageChange change = SecureStorageChange(
      'token',
      SecureStorageChangeKind.written,
    );
    expect(change.toString(), contains('written'));
    expect(change.toString(), isNot(contains('token')));
  });
}
