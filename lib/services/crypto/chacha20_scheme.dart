import 'dart:convert';
import 'dart:math';
import 'package:cryptography/cryptography.dart' as crypto;
import 'cipher_scheme.dart';

class ChaCha20Scheme implements CipherScheme {
  @override
  String get name => "chacha20";

  List<int>? _key;

  @override
  Future<void> deriveKeys(List<int> sharedSecret) async {
    final hkdf = crypto.Hkdf(hmac: crypto.Hmac.sha256(), outputLength: 32);
    final salt = List<int>.filled(32, 0);
    final derivedKey = await hkdf.deriveKey(
      secretKey: crypto.SecretKey(sharedSecret),
      nonce: salt,
      info: utf8.encode("greenbuck-chacha20-poly1305"),
    );

    _key = await derivedKey.extractBytes();
  }

  @override
  Future<Map<String, dynamic>> encrypt(String plaintextJson) async{
    if (_key == null) {
      throw Exception("Keys are not derived");
    }

    final nonce = List<int>.generate(12, (_) => Random.secure().nextInt(256));

    final algorithm = crypto.Chacha20.poly1305Aead();
    final secretBox = await algorithm.encrypt(
      utf8.encode(plaintextJson),
      secretKey: crypto.SecretKey(_key!),
      nonce: nonce,
    );

    final combined = secretBox.cipherText + secretBox.mac.bytes;

    final envelope = {
      "nonce": base64Encode(nonce),
      "ciphertext": base64Encode(combined),
    };

    return envelope;
  }

  @override
  Future<String> decrypt(Map<String, dynamic> envelope) async {
    if(_key == null){
      throw Exception("Keys are not derived");
    }
    
    final nonce = base64Decode(envelope["nonce"]);
    final combined = base64Decode(envelope["ciphertext"]);

    final tagLength = 16;
    final cipherTextOnly = combined.sublist(0, combined.length - tagLength);
    final tag = combined.sublist(combined.length - tagLength);

    final algorithm = crypto.Chacha20.poly1305Aead();
    final plaintextBytes = await algorithm.decrypt(
      crypto.SecretBox(cipherTextOnly, nonce: nonce, mac:crypto.Mac(tag)),
      secretKey: crypto.SecretKey(_key!),
    );

    return utf8.decode(plaintextBytes);
  }
}