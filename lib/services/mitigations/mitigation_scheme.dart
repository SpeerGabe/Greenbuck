/*
Base class for client-side mitigation schemes. The defaults leave traffic untouched.
- batchRequests: queue requests and send them together (batching)
- padRequests: send every request at the same size on the wire (padding)
- shapeBody: pads the plaintext JSON body before encryption (padding)
- padWireBody: pads the final body, plaintext or encrypted envelope (padding)
- headerPad: value for the X-Pad request header (padding)
Jitter and constant-rate are applied by the server; their client schemes only carry the label.
*/

abstract class MitigationScheme {
  String get name;

  // true when requst should be queued and sent together for batching
  bool get batchRequests => false;

  bool get padRequests => false;

  String shapeBody(String plaintextJson) => plaintextJson;

  String padWireBody(String body) => body;

  String headerPad({required String method, required String path, String? authorization}) => '';
}
