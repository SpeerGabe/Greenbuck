/*
Abstract class for client side traffic shaping mitigation schemes. Each mitigation scheme should implement this class and provide its own implementation of the following methods:
- shapeBody: this method is responsible for shaping the body of the request according to the mitigation scheme's logic. (return plaintext if no shaping is needed)
- beforeSend(): runs just before a call start for jitter mitigation scheme 
- afterResponse(): runs just after a call ends for constant timing mitigation scheme
*/

abstract class MitigationScheme {
  String get name;

  String shapeBody(String plaintextJson) => plaintextJson;

  Future<void> beforeSend() async {}

  Future<void> afterResponse(Duration elapsed) async {}
}