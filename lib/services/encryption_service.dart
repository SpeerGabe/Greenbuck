//service to encrypt and decrypt data

import 'dart:convert';
import 'package:cryptography/cryptography.dart' as crypto;
import 'crypto/cipher_scheme.dart';
import 'crypto/aes_cbc_scheme.dart';
import 'crypto/aes_gcm_scheme.dart';
//import 'crypto/chacha20_scheme.dart';

class EncryptionService {
  final _x25519 = crypto.X25519();
  late crypto.SimpleKeyPair _clientKeyPair; //might be null

  // list of different encryption schemes
  final Map<String, CipherScheme> availableSchemes = {
    "aescbc": AesCbcScheme(),
    "aesgcm": AesGcmScheme(),
    //"chacha20": ChaCha20Scheme()
  };

  String activeSchemeName = "aescbc";
  String activeMitigation = "none";

  void setActiveScheme(String schemeName) {
    if (availableSchemes.containsKey(schemeName)) {
      activeSchemeName = schemeName;
    }
  }

  // looks up the selected scheme by name
  CipherScheme get activeScheme => availableSchemes[activeSchemeName]!;

  //creates new keypair for this login and returns the public key
  Future<String> generateClientPublicKey() async {
    _clientKeyPair = await _x25519.newKeyPair();
    final publicKey = await _clientKeyPair.extractPublicKey();
    return base64Encode(publicKey.bytes);
  }

  //combines private key with server's public key  to get a shared secret
  //derived per scheme keys from it so every cipher is ready to use within the session
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

  // encrypts plaintext using the active scheme
  Future<Map<String, dynamic>> encryptPayload(String plaintextJson) async {
    return activeScheme.encrypt(plaintextJson);
  }

  // decrypts an envelope back into the original plaintext
  Future<String> decryptPayload(Map<String, dynamic> envelope) async {
    return activeScheme.decrypt(envelope);
  }
}