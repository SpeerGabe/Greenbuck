import 'mitigation_scheme.dart';

class BatchingMitigation extends MitigationScheme {
  // how long the window stays open to add requests
  static const int windowMs = 300;

  //must stay at or below server batch size
  static const int maxBatchSize = 20;

  @override
  String get name => "batching";

  @override
  bool get batchRequests => true;
}