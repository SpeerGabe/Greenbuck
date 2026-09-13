abstract class CipherScheme {
  String get name;

  Future<void> deriveKeys(List<int> sharedSecret);

  Future<Map<String, dynamic>> encrypt(String plaintextJson);

  Future<String> decrypt(Map<String, dynamic> envelope);
}