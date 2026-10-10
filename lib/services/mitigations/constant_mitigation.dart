import 'mitigation_scheme.dart';

class ConstantMitigation extends MitigationScheme {
  // must exceed the slowest real call, othyerwise that call will stand out  
  static const int targetDelayMs = 250; // 250ms. mirrors the server sided constant timing mitigation scheme

  @override
  String get name => 'constant';

  @override
  Future<void> afterResponse(Duration elapsed) async {
    final remainingDelayMs = targetDelayMs - elapsed.inMilliseconds;

    // call is already slower than the target wont be slowed
    if (remainingDelayMs > 0) {
      await Future.delayed(Duration(milliseconds: remainingDelayMs));
    }
  }
}