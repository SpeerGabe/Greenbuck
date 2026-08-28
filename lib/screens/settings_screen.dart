// Admin settings for the GreenBuck research instrument.
// PIN-gated. Toggles drive the X-* headers on every API request.

import 'package:flutter/material.dart';
import '../services/api_service.dart';
import 'login_screen.dart';

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});

  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  // Demo gate, not real security. See master build doc 5.7.
  static const String _adminPin = '4242';

  bool _unlocked = false;
  final _pinController = TextEditingController();
  String? _pinError;

  // Singleton — toggle changes affect every screen's requests.
  final ApiService _apiService = ApiService();

  // Local mirrors of ApiService state for the radio buttons.
  late String _mode;
  late String _encryption;
  late String _mitigation;
  late String _platform;

  @override
  void initState() {
    super.initState();
    _mode = _apiService.mode;
    _encryption = _apiService.encryption;
    _mitigation = _apiService.mitigation;
    _platform = _apiService.platform;
  }

  @override
  void dispose() {
    _pinController.dispose();
    super.dispose();
  }

  void _attemptUnlock() {
    if (_pinController.text == _adminPin) {
      setState(() {
        _unlocked = true;
        _pinError = null;
      });
    } else {
      setState(() => _pinError = 'Incorrect PIN');
    }
  }

  // Toggle setters update UI state and ApiService together.
  void _setMode(String v) {
    setState(() => _mode = v);
    _apiService.mode = v;
  }

  void _setEncryption(String v) {
    setState(() => _encryption = v);
    _apiService.encryption = v;
  }

  void _setMitigation(String v) {
    setState(() => _mitigation = v);
    _apiService.mitigation = v;
  }

  void _setPlatform(String v) {
    setState(() => _platform = v);
    _apiService.platform = v;
  }

  // Fires POST /auth/logout, then pops back to the login screen.
  Future<void> _handleLogout() async {
    try {
      await _apiService.logout(_apiService.authToken ?? 'no-token');
    } catch (e) {
      debugPrint('Logout failed: $e');
    }
    _apiService.authToken = null;
    if (!mounted) return;
    Navigator.of(context).pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const LoginScreen()),
      (route) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        backgroundColor: Colors.green,
        foregroundColor: Colors.white,
      ),
      body: _unlocked ? _buildSettings() : _buildPinGate(),
    );
  }

  // PIN gate shown until admin unlocks.
  Widget _buildPinGate() {
    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SizedBox(height: 40),
          const Icon(Icons.lock, size: 64, color: Colors.green),
          const SizedBox(height: 16),
          const Text('Admin Settings',
            style: TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          const Text('Enter PIN to access research configuration.',
            style: TextStyle(color: Colors.grey)),
          const SizedBox(height: 24),
          TextField(
            controller: _pinController,
            keyboardType: TextInputType.number,
            obscureText: true,
            decoration: InputDecoration(
              labelText: 'PIN',
              border: const OutlineInputBorder(),
              errorText: _pinError,
            ),
            onSubmitted: (_) => _attemptUnlock(),
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.green,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 16),
              ),
              onPressed: _attemptUnlock,
              child: const Text('Unlock', style: TextStyle(fontSize: 16)),
            ),
          ),
        ],
      ),
    );
  }

  // Settings panel shown after unlock.
  Widget _buildSettings() {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        _buildSection(
          title: 'System Mode',
          subtitle: 'A = plaintext baseline · B = encrypted + mitigations active',
          child: Column(
            children: [
              _buildRadio('System A', 'systemA', _mode, _setMode),
              _buildRadio('System B', 'systemB', _mode, _setMode),
            ],
          ),
        ),
        _buildSection(
          title: 'Encryption Algorithm',
          subtitle: 'Cipher used for field-level encryption in System B',
          child: Column(
            children: [
              _buildRadio('None', 'none', _encryption, _setEncryption),
              _buildRadio('AES-GCM', 'aesgcm', _encryption, _setEncryption),
              _buildRadio('ChaCha20-Poly1305', 'chacha20', _encryption, _setEncryption),
              _buildRadio('AES-256-CBC', 'aescbc', _encryption, _setEncryption),
            ],
          ),
        ),
        _buildSection(
          title: 'Mitigation State',
          subtitle: 'Server-side traffic shaping for timing defense',
          child: Column(
            children: [
              _buildRadio('None (control)', 'none', _mitigation, _setMitigation),
              _buildRadio('Response padding', 'padding', _mitigation, _setMitigation),
              _buildRadio('Timing jitter', 'jitter', _mitigation, _setMitigation),
              _buildRadio('Constant-rate', 'constant', _mitigation, _setMitigation),
            ],
          ),
        ),
        _buildSection(
          title: 'Platform Tag',
          subtitle: 'Reported to backend in X-Platform header for capture labeling',
          child: Column(
            children: [
              _buildRadio('Android', 'android', _platform, _setPlatform),
              _buildRadio('iOS', 'ios', _platform, _setPlatform),
            ],
          ),
        ),
        _buildSection(
          title: 'Session',
          subtitle: 'Log out and return to the login screen',
          child: SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.red,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 12),
              ),
              icon: const Icon(Icons.logout),
              label: const Text('Log Out'),
              onPressed: _handleLogout,
            ),
          ),
        ),
        const SizedBox(height: 8),
        // Always-visible readout for demo confirmation.
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Colors.green.withOpacity(0.1),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: Colors.green.withOpacity(0.3)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Active Configuration',
                style: TextStyle(fontWeight: FontWeight.bold, color: Colors.green)),
              const SizedBox(height: 6),
              Text('Mode:        $_mode'),
              Text('Encryption:  $_encryption'),
              Text('Mitigation:  $_mitigation'),
              Text('Platform:    $_platform'),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildSection({
    required String title,
    required String subtitle,
    required Widget child,
  }) {
    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(12),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
            const SizedBox(height: 2),
            Text(subtitle, style: const TextStyle(fontSize: 12, color: Colors.grey)),
            const SizedBox(height: 8),
            child,
          ],
        ),
      ),
    );
  }

  Widget _buildRadio(
    String label,
    String value,
    String groupValue,
    void Function(String) onChanged,
  ) {
    return RadioListTile<String>(
      title: Text(label),
      value: value,
      groupValue: groupValue,
      activeColor: Colors.green,
      contentPadding: EdgeInsets.zero,
      dense: true,
      onChanged: (v) { if (v != null) onChanged(v); },
    );
  }
}