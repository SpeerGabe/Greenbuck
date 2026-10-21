/*
  random padding mitigation scheme. Every request gets a random amount of padding:
  - padWireBody: adds 1..maxBodyPadBytes filler bytes to the final body (plaintext or encrypted
    envelope) in a "_wpad" key
  - headerPad: X-Pad header value of 1..maxHeaderPadBytes bytes
  Both are drawn fresh for every request. GET requests carry a body too, like fixed padding.
  The server ignores the key and the header, and pads its responses the same way.
*/

import 'dart:math';
import 'mitigation_scheme.dart';
import 'padding_mitigation.dart';

class RandomPaddingMitigation extends MitigationScheme {
  static const int maxBodyPadBytes = 4096; // mirrors RANDOM_PAD_MAX_BYTES in api/main.py
  static const int maxHeaderPadBytes = 256; // mirrors RANDOM_HEADER_PAD_MAX_BYTES in api/main.py

  final Random _random = Random.secure();

  @override
  String get name => 'random_padding';

  @override
  bool get padRequests => true;

  @override
  String padWireBody(String body) => insertFiller(body, 1 + _random.nextInt(maxBodyPadBytes), '_wpad');

  @override
  String headerPad({required String method, required String path, String? authorization}) =>
      'x' * (1 + _random.nextInt(maxHeaderPadBytes));
}
