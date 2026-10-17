import 'dart:async';
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:get_x_storage_secure/get_x_storage_secure.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: DefaultTabController(
        length: 2,
        child: Scaffold(
          appBar: AppBar(
            title: const Text('Secret storage'),
            bottom: const TabBar(
              tabs: <Widget>[
                Tab(text: 'Vault'),
                Tab(text: 'Key-value'),
              ],
            ),
          ),
          body: const TabBarView(
            children: <Widget>[VaultPage(), StoragePage()],
          ),
        ),
      ),
    );
  }
}

/// Reports what an operation did, never what a secret was.
///
/// Every page runs its calls through here so the failure modes the package
/// distinguishes stay visible in the log: an OS facility that cannot be used,
/// one call that failed on a usable facility, a secret waiting for the user to
/// authenticate, and a name the store refused to accept.
Future<void> logOperation(
  List<String> log,
  String label,
  Future<String> Function() action,
) async {
  String result;
  try {
    result = await action();
  } on VaultUnavailableException catch (e) {
    result = 'unavailable: ${e.message}';
  } on VaultAuthenticationRequiredException catch (e) {
    result = 'needs authentication (osCode ${e.osCode})';
  } on VaultOperationException catch (e) {
    result = 'failed (osCode ${e.osCode})';
  } on UnsupportedError catch (e) {
    result = 'unsupported: ${e.message}';
  } on ArgumentError catch (e) {
    result = 'rejected: ${e.message}';
  }
  log.insert(0, '$label -> $result');
}

/// Drives [createPlatformVault] the way an app would: keep a master key that the
/// OS protects, and never print its bytes.
class VaultPage extends StatefulWidget {
  const VaultPage({super.key});

  @override
  State<VaultPage> createState() => _VaultPageState();
}

class _VaultPageState extends State<VaultPage> {
  static const String _alias = 'master_key';

  SecretVault? _vaultInstance;
  SecretVault get _vault => _vaultInstance ??= createPlatformVault();
  final List<String> _log = <String>[];
  bool _busy = false;

  Future<void> _run(String label, Future<String> Function() action) async {
    setState(() => _busy = true);
    await logOperation(_log, label, action);
    if (mounted) {
      setState(() => _busy = false);
    }
  }

  Future<String> _write() async {
    // A stand-in for a real key; an app would generate this once and store it.
    final Uint8List secret = Uint8List.fromList(
      List<int>.generate(32, (int i) => (i * 7 + 3) & 0xff),
    );
    await _vault.write(_alias, secret);
    return 'stored ${secret.length} bytes';
  }

  Future<String> _read() async {
    final Uint8List? secret = await _vault.read(_alias);
    if (secret == null) {
      return 'no secret (never stored, or the OS lost its key)';
    }
    return 'recovered ${secret.length} bytes';
  }

  Future<String> _contains() async =>
      (await _vault.contains(_alias)) ? 'present' : 'absent';

  Future<String> _delete() async {
    await _vault.delete(_alias);
    return 'deleted';
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: <Widget>[
              _button('Write', _write),
              _button('Read', _read),
              _button('Contains', _contains),
              _button('Delete', _delete),
            ],
          ),
          const SizedBox(height: 12),
          Expanded(child: _logList()),
        ],
      ),
    );
  }

  Widget _logList() => ListView.builder(
    itemCount: _log.length,
    itemBuilder: (BuildContext context, int index) =>
        Text(_log[index], style: const TextStyle(fontSize: 15)),
  );

  Widget _button(String label, Future<String> Function() action) {
    return ElevatedButton(
      onPressed: _busy ? null : () => _run(label, action),
      child: Text(label),
    );
  }
}

/// Drives [SecureStorage]: ordinary text keys, values of any length, and the
/// index that makes them listable.
class StoragePage extends StatefulWidget {
  const StoragePage({super.key});

  @override
  State<StoragePage> createState() => _StoragePageState();
}

class _StoragePageState extends State<StoragePage> {
  SecureStorage? _storeInstance;
  SecureStorage get _store => _storeInstance ??= SecureStorage();

  final TextEditingController _key = TextEditingController(
    text: 'session_token',
  );
  final TextEditingController _value = TextEditingController();
  final List<String> _log = <String>[];
  StreamSubscription<SecureStorageChange>? _sub;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    try {
      _sub = _store.changes.listen((SecureStorageChange change) {
        if (mounted) {
          setState(() => _log.insert(0, 'change -> $change'));
        }
      });
    } on UnsupportedError {
      // Ignored on web/unsupported platforms where SecureStorage throws on creation.
    }
  }

  @override
  void dispose() {
    _sub?.cancel();
    if (_storeInstance != null) {
      _storeInstance!.dispose();
    }
    _key.dispose();
    _value.dispose();
    super.dispose();
  }

  Future<void> _run(String label, Future<String> Function() action) async {
    setState(() => _busy = true);
    await logOperation(_log, label, action);
    if (mounted) {
      setState(() => _busy = false);
    }
  }

  String get _keyText => _key.text;

  Future<String> _save() async {
    await _store.write(_keyText, _value.text);
    return 'saved ${_value.text.characters.length} characters';
  }

  Future<String> _read() async {
    final String? value = await _store.read(_keyText);
    if (value == null) {
      return 'no value (never stored, or the OS lost its key)';
    }
    return 'read ${value.characters.length} characters';
  }

  Future<String> _contains() async =>
      (await _store.containsKey(_keyText)) ? 'present' : 'absent';

  Future<String> _delete() async {
    await _store.delete(_keyText);
    return 'deleted';
  }

  Future<String> _keys() async {
    final List<String> keys = await _store.getKeys();
    if (keys.isEmpty) {
      return 'no keys';
    }
    return '${keys.length} key${keys.length == 1 ? '' : 's'}: '
        '${keys.join(', ')}';
  }

  Future<String> _deleteAll() async {
    await _store.deleteAll();
    return 'all values removed';
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: <Widget>[
          TextField(
            controller: _key,
            decoration: const InputDecoration(labelText: 'Key'),
          ),
          TextField(
            controller: _value,
            decoration: const InputDecoration(labelText: 'Value'),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: <Widget>[
              _button('Save', _save),
              _button('Read', _read),
              _button('Contains', _contains),
              _button('Keys', _keys),
              _button('Delete', _delete),
              _button('Delete all', _deleteAll),
            ],
          ),
          const SizedBox(height: 12),
          Expanded(
            child: ListView.builder(
              itemCount: _log.length,
              itemBuilder: (BuildContext context, int index) =>
                  Text(_log[index], style: const TextStyle(fontSize: 15)),
            ),
          ),
        ],
      ),
    );
  }

  Widget _button(String label, Future<String> Function() action) {
    return ElevatedButton(
      onPressed: _busy ? null : () => _run(label, action),
      child: Text(label),
    );
  }
}
