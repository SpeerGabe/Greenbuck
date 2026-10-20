import 'mitigation_scheme.dart';

// Jitter is applied by the server (api/main.py); the client only sends the label.
class JitterMitigation extends MitigationScheme {
  @override
  String get name => 'jitter';
}
