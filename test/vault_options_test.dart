import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:get_x_storage_secure/src/vault/secret_vault.dart';
import 'package:get_x_storage_secure/src/vault/vault_internals.dart';
import 'package:get_x_storage_secure/src/vault/vault_options.dart';

void main() {
  group('VaultOptions', () {
    test('accepts a cap up to the ceiling', () {
      expect(() => const VaultOptions().validate(), returnsNormally);
      expect(
        () =>
            VaultOptions(maxSecretBytes: kMaxConfigurableVaultSecretBytes)
                .validate(),
        returnsNormally,
      );
    });

    test('rejects a cap outside 1..ceiling', () {
      for (final int bad in <int>[
        0,
        -1,
        kMaxConfigurableVaultSecretBytes + 1,
      ]) {
        expect(
          () => VaultOptions(maxSecretBytes: bad).validate(),
          throwsA(isA<ArgumentError>()),
          reason: 'maxSecretBytes $bad must be rejected',
        );
      }
    });

    test('defaults to the tightest Apple class, not synced', () {
      const AppleVaultOptions options = AppleVaultOptions();
      expect(
        options.accessibility,
        AppleAccessibility.whenUnlockedThisDeviceOnly,
      );
      expect(options.synchronizable, isFalse);
      expect(options.accessGroup, isNull);
      expect(options.validate, returnsNormally);
    });

    test('syncing needs a class that can leave the device', () {
      for (final AppleAccessibility class_ in AppleAccessibility.values) {
        final AppleVaultOptions options = AppleVaultOptions(
          accessibility: class_,
          synchronizable: true,
        );
        if (class_.isThisDeviceOnly) {
          expect(
            options.validate,
            throwsA(isA<ArgumentError>()),
            reason: '$class_ cannot sync',
          );
        } else {
          expect(options.validate, returnsNormally);
        }
      }
    });

    test('an access group follows the alias character rules', () {
      expect(
        () => const AppleVaultOptions(accessGroup: 'group one').validate(),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () =>
            const AppleVaultOptions(accessGroup: '8040H6QF9P.com.app.shared')
                .validate(),
        returnsNormally,
      );
    });
  });

  group('authentication gating', () {
    test('an Apple gate needs the text of the dialog it will show', () {
      for (final AppleAuthentication gate in AppleAuthentication.values) {
        if (gate.isRequired) {
          expect(
            () => AppleVaultOptions(authentication: gate).validate(),
            throwsA(isA<ArgumentError>()),
            reason: '$gate needs a prompt',
          );
          expect(
            () => AppleVaultOptions(
              authentication: gate,
              authenticationPrompt: '',
            ).validate(),
            throwsA(isA<ArgumentError>()),
          );
          expect(
            () => AppleVaultOptions(
              authentication: gate,
              authenticationPrompt: 'Unlock your vault',
            ).validate(),
            returnsNormally,
          );
        } else {
          expect(
            () => AppleVaultOptions(authentication: gate).validate(),
            returnsNormally,
          );
        }
      }
    });

    test('Android keeps its timeout inside the documented window', () {
      expect(() => const AndroidVaultOptions().validate(), returnsNormally);
      expect(
        () => AndroidVaultOptions(
          requireUserAuthentication: true,
          authenticationTimeoutSeconds: 0,
        ).validate(),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => AndroidVaultOptions(
          requireUserAuthentication: true,
          authenticationTimeoutSeconds: kMaxAuthenticationTimeoutSeconds + 1,
        ).validate(),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => AndroidVaultOptions(
          requireUserAuthentication: true,
          authenticationTimeoutSeconds: kMaxAuthenticationTimeoutSeconds,
        ).validate(),
        returnsNormally,
      );
      // Without the gate the timeout is never sent to the keystore.
      expect(
        () => AndroidVaultOptions(authenticationTimeoutSeconds: 0).validate(),
        returnsNormally,
      );
    });

    test('VaultOptions validates the gate of each platform it carries', () {
      expect(
        () => VaultOptions(
          apple: const AppleVaultOptions(
            authentication: AppleAuthentication.userPresence,
          ),
        ).validate(),
        throwsA(isA<ArgumentError>()),
      );
      expect(
        () => VaultOptions(
          android: const AndroidVaultOptions(
            requireUserAuthentication: true,
            authenticationTimeoutSeconds: 9999,
          ),
        ).validate(),
        throwsA(isA<ArgumentError>()),
      );
    });
  });

  group('vaultCheckWire', () {
    test('reports an authentication gate as retryable, not broken', () {
      expect(
        () => vaultCheckWire('read "token"', vaultAuthRequired(osCode: -25308)),
        throwsA(isA<VaultAuthenticationRequiredException>()),
      );
      void check() => vaultCheckWire(
        'read "token"',
        vaultAuthRequired(osCode: -25308, detail: 'the device is locked'),
      );
      expect(check, throwsA(isA<VaultAuthenticationRequiredException>()));
      try {
        check();
        fail('the wire said the user must authenticate');
      } on VaultAuthenticationRequiredException catch (error) {
        expect(error.osCode, -25308);
        expect(error.toString(), contains('-25308'));
        expect(error.message, contains('the device is locked'));
      }
      expect(
        () => vaultCheckWire('read "token"', vaultOk(Uint8List(1))),
        returnsNormally,
      );
    });

    test('an authentication message carries no payload', () {
      final VaultWire wire = vaultAuthRequired(
        osCode: 7,
        detail: 'correct horse battery staple',
      );
      expect(wire.data, isNull);
      expect(wire.detail, contains('correct horse battery staple'));
    });
  });

  group('validateSecret', () {
    test('uses the cap of the vault it is called for', () {
      expect(
        () => validateSecret(Uint8List(1025), kMaxVaultSecretBytes),
        throwsA(isA<ArgumentError>()),
      );
      expect(() => validateSecret(Uint8List(1025), 2048), returnsNormally);
      expect(
        () => validateSecret(Uint8List(0), 2048),
        throwsA(isA<ArgumentError>()),
      );
    });
  });
}
