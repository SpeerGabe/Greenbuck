/*
Abstract class to implement different Cipher Schemes for encrypting and decrypting data, alongside generating keys
*/

abstract class CipherScheme {
  String get name;

  //derives this scheme's symmetric encryption key from the shared secret with HKDF
  Future<void> deriveKeys(List<int> sharedSecret);

  //encrypts plaintext and returns encrypted envelope
  Future<Map<String, dynamic>> encrypt(String plaintextJson);

  //decrypts envelope and returns plaintext
  Future<String> decrypt(Map<String, dynamic> envelope);
}