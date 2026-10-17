import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure_example/main.dart' as app;
import 'package:integration_test/integration_test.dart';

/// Drives the demo exactly as a user would, so a real build exercises the whole
/// stack: the platform choice inside [createPlatformVault], the worker isolate
/// each call runs on, and the OS facility behind it.
///
/// Every finder is scoped to the page it belongs to, because the two tabs of
/// the demo have buttons with the same labels.
///
/// Run it with `flutter test integration_test -d windows`, or
/// `flutter test integration_test -d <device>` for a phone — whose screen has to
/// stay on, since a sleeping device delivers no frames to pump.
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('a master key is written, recovered and deleted', (
    WidgetTester tester,
  ) async {
    app.main();
    await pumpUntil(
      tester,
      () => button(app.VaultPage, 'Write').evaluate().isNotEmpty,
      'the four vault buttons',
    );

    await press(tester, app.VaultPage, 'Delete', 'deleted');
    await press(tester, app.VaultPage, 'Contains', 'absent');
    await press(
      tester,
      app.VaultPage,
      'Read',
      'no secret (never stored, or the OS lost its key)',
    );
    await press(tester, app.VaultPage, 'Write', 'stored 32 bytes');
    await press(tester, app.VaultPage, 'Contains', 'present');
    await press(tester, app.VaultPage, 'Read', 'recovered 32 bytes');
    await press(tester, app.VaultPage, 'Delete', 'deleted');
    await press(
      tester,
      app.VaultPage,
      'Read',
      'no secret (never stored, or the OS lost its key)',
    );
  });

  testWidgets('a text key–value pair is saved, listed and removed', (
    WidgetTester tester,
  ) async {
    app.main();
    await pumpUntil(
      tester,
      () => find.text('Key-value').evaluate().isNotEmpty,
      'the two tabs',
    );
    await tester.tap(find.text('Key-value'));
    await pumpUntil(
      tester,
      () => button(app.StoragePage, 'Keys').evaluate().isNotEmpty,
      'the key-value buttons',
    );

    await enterValue(tester, 'demo-secret');
    await press(tester, app.StoragePage, 'Save', 'saved 11 characters');
    await press(tester, app.StoragePage, 'Contains', 'present');
    await press(tester, app.StoragePage, 'Read', 'read 11 characters');
    await press(tester, app.StoragePage, 'Keys', '1 key: session_token');
    await press(tester, app.StoragePage, 'Delete', 'deleted');
    await press(
      tester,
      app.StoragePage,
      'Read',
      'no value (never stored, or the OS lost its key)',
    );
    await press(tester, app.StoragePage, 'Keys', 'no keys');
  });
}

/// Taps [label] inside [page] and waits for [result] to become the newest
/// operation it reports.
///
/// Change notifications are skipped when finding that newest line: a write also
/// announces itself on [SecureStorage.changes], and that entry can arrive after
/// the result.
Future<void> press(
  WidgetTester tester,
  Type page,
  String label,
  String result,
) async {
  final String expected = '$label -> $result';
  await tester.tap(button(page, label));
  await pumpUntil(
    tester,
    () => lastOperation(tester, page) == expected,
    expected,
  );
}

Finder button(Type page, String label) => find.descendant(
  of: find.byType(page),
  matching: find.widgetWithText(ElevatedButton, label),
);

/// The line [page] reported for its most recent button press, if any.
String? lastOperation(WidgetTester tester, Type page) {
  final Finder rows = find.descendant(
    of: logList(page),
    matching: find.byType(Text),
  );
  for (final Element element in rows.evaluate()) {
    final String line = (element.widget as Text).data ?? '';
    if (!line.startsWith('change -> ')) {
      return line;
    }
  }
  return null;
}

Finder logList(Type page) => find
    .descendant(of: find.byType(page), matching: find.byType(ListView))
    .first;

/// Types [text] into the storage page's value field.
Future<void> enterValue(WidgetTester tester, String text) async {
  final Finder fields = find.descendant(
    of: find.byType(app.StoragePage),
    matching: find.byType(TextField),
  );
  await tester.enterText(fields.last, text);
  await tester.pump();
}

/// Pumps in small steps until [done] holds.
///
/// Bounded on purpose: the vault answers from a throwaway isolate, so the wait
/// needs real frames rather than a fake clock, and a call that never returns has
/// to end the test with a reason instead of hanging it.
Future<void> pumpUntil(
  WidgetTester tester,
  bool Function() done,
  String what,
) async {
  for (int attempt = 0; attempt < 200 && !done(); attempt++) {
    await tester.pump(const Duration(milliseconds: 50));
  }
  expect(done(), isTrue, reason: 'timed out waiting for $what');
}
