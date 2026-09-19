//AES-256-GCM implementation of CipherScheme

import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart' as crypto;
import 'cipher_scheme.dart';

class AesGcmScheme implements CipherScheme{
  @override
  String get name => "aesgcm";

  List<int>? _aesKey;

  @override
  Future<void> deriveKeys(List<int> sharedSecret) async {
    final hkdf = crypto.Hkdf(hmac: crypto.Hmac.sha256(), outputLength: 32);
    final salt = List<int>.filled(32, 0); // match salt with server salt
    final derivedKey = await hkdf.deriveKey(
      secretKey: crypto.SecretKey(sharedSecret),
      nonce: salt,
      info: utf8.encode("greenbuck-aes-gcm"), // match with server info
      );

      _aesKey = await derivedKey.extractBytes(); // 256 bit aes key
  }

  @override
  Future<Map<String, dynamic>> encrypt(String plaintextJson) async{
    if(_aesKey == null) {
      throw Exception("Keys are not derived");
    }

    final nonce = List<int>.generate(12, (_) => Random.secure().nextInt(256)); // Prevents identical plaintexts from producing identical ciphertext

    final algorithm = crypto.AesGcm.with256bits();
    final secretBox = await algorithm.encrypt(
      utf8.encode(plaintextJson),
      secretKey: crypto.SecretKey(_aesKey!),
      nonce: nonce,
    );

    final combined = secretBox.cipherText + secretBox.mac.bytes; //puts together the ciphertext and tag. the tag is 128 bits/16 bytes

    final envelope = {
      "nonce": base64Encode(nonce),
      "ciphertext": base64Encode(combined),
    };

    return envelope;
  }

  @override
  Future<String> decrypt(Map<String, dynamic> envelope) async {
    if (_aesKey == null){
      throw Exception("Keys are not derived");
    }

    final nonce = base64Decode(envelope["nonce"]);
    final combined = base64Decode(envelope["ciphertext"]);

    //separate the tag and the text
    final tagLength = 16;
    final cipherTextOnly = combined.sublist(0, combined.length - tagLength);
    final tag = combined.sublist(combined.length - tagLength);

    //decrypt the envelope using the tag to check integrity
    final algorithm = crypto.AesGcm.with256bits();
    final plaintextBytes = await algorithm.decrypt(
      crypto.SecretBox(cipherTextOnly, nonce: nonce, mac: crypto.Mac(tag)),
      secretKey: crypto.SecretKey(_aesKey!),
    );

    return utf8.decode(plaintextBytes);
  }

}