import 'mitigation_scheme.dart';

// Constant-rate is applied by the server (api/main.py); the client only sends the label.
class ConstantMitigation extends MitigationScheme {
  @override
  String get name => 'constant';
}
