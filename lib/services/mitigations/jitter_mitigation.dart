import 'dart:math';
import 'mitigation_scheme.dart';

class JitterMitigation extends MitigationScheme {
  // Sync with server side jitter mitigation scheme.
  static const int minDelayMs = 0; // minimum delay in milliseconds
  static const int maxDelayMs = 50; // maximum delay in milliseconds

  final Random _random = Random.secure();

  @override
  String get name => 'jitter';

  @override
  Future<void> beforeSend() async {
    final delayMs = minDelayMs + _random.nextInt(maxDelayMs - minDelayMs + 1);
    await Future.delayed(Duration(milliseconds: delayMs));
  }
}