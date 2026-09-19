// AES-256-CBC  implementation of CipherScheme

import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart' as crypto;
import 'package:encrypt/encrypt.dart' as aes_package;
import 'cipher_scheme.dart';

class AesCbcScheme implements CipherScheme {
  @override
  String get name => "aescbc";

  aes_package.Key? _aesKey;

  @override
  Future<void> deriveKeys(List<int> sharedSecret) async {
    final hkdf = crypto.Hkdf(hmac: crypto.Hmac.sha256(), outputLength: 32);
    final salt = List<int>.filled(32, 0); //match with server's salt
    
    final derivedKey = await hkdf.deriveKey(
      secretKey: crypto.SecretKey(sharedSecret),
      nonce: salt,
      info: utf8.encode("greenbuck-aes-cbc"), //match with server's info
    );

    final keyBytes = await derivedKey.extractBytes();
    _aesKey = aes_package.Key(Uint8List.fromList(keyBytes)); // this is the only key used. There is no integrity checks for the data
  }

  @override
  Future<Map<String, dynamic>> encrypt(String plaintextJson) async {
    if (_aesKey == null) {
      throw Exception("Keys not derived");
    }
    final iv = aes_package.IV.fromSecureRandom(16); //IV prevents two packets from looking the same even if they contain the same data. Safe to send as it is not derived from any keys
    final encrypter = aes_package.Encrypter(
      aes_package.AES(_aesKey!, mode: aes_package.AESMode.cbc, padding: 'PKCS7') //AES-CBC is a blocking encryption scheme, data has to be padded to fill out the last block. PKCS7 is used for this
    );
    final encrypted = encrypter.encrypt(plaintextJson, iv: iv);

    final envelope = {
      "iv": iv.base64,
      "ciphertext": encrypted.base64,
    };
    return envelope;
  }

    @override
    Future<String> decrypt(Map<String, dynamic> envelope) async{
      if (_aesKey == null) {
        throw Exception("Keys not derived");
      }
      final iv = aes_package.IV.fromBase64(envelope["iv"]);
      final ciphertext = aes_package.Encrypted.fromBase64(envelope["ciphertext"]);

      final encrypter = aes_package.Encrypter(
        aes_package.AES(_aesKey!, mode: aes_package.AESMode.cbc, padding: 'PKCS7')
      );

      final decryptedText = encrypter.decrypt(ciphertext, iv: iv);
      return decryptedText;
    }
}