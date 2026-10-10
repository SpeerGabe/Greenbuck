/*
  traffic is untouched, only name is implemented
*/
import 'mitigation_scheme.dart';

class NoMitigation extends MitigationScheme {
  @override
  String get name => 'none';
}