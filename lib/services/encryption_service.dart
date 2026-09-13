import 'dart:convert';
import 'package:cryptography/cryptography.dart' as crypto;
import 'crypto/cipher_scheme.dart';
import 'crypto/aes_cbc_scheme.dart';
//import 'crypto/aes_gcm_scheme.dart';
//import 'crypto/chacha20_scheme.dart';

class EncryptionService {
  final _x25519 = crypto.X25519();
  late crypto.SimpleKeyPair _clientKeyPair;

  final Map<String, CipherScheme> availableSchemes = {
    "aescbc": AesCbcScheme(),
    //"aesgcm": AesGcmScheme(),
    //"chacha20": ChaCha20Scheme()
  };

  String activeSchemeName = "aescbc";
  String activeMitigation = "none";

  CipherScheme get activeScheme => availableSchemes[activeSchemeName]!;

  Future<String> generateClientPublicKey() async {
    _clientKeyPair = await _x25519.newKeyPair();
    final publicKey = await _clientKeyPair.extractPublicKey();
    return base64Encode(publicKey.bytes);
  }

  Future<void> deriveSessionKeys(String serverPublicKeyBase64) async {
    final serverKeyBytes = base64Decode(serverPublicKeyBase64);
    final serverPublicKey = crypto.SimplePublicKey(
      serverKeyBytes,
      type: crypto.KeyPairType.x25519,
    );

    final sharedSecret = await _x25519.sharedSecretKey(
      keyPair: _clientKeyPair,
      remotePublicKey: serverPublicKey,
    );

    final sharedSecretBytes = await sharedSecret.extractBytes();

    for (var scheme in availableSchemes.values) {
      await scheme.deriveKeys(sharedSecretBytes);
    }
  }

  Future<Map<String, dynamic>> encryptPayload(String plaintextJson) async {
    return activeScheme.encrypt(plaintextJson);
  }

  Future<String> decryptPayload(Map<String, dynamic> envelope) async {
    return activeScheme.decrypt(envelope);
  }
}