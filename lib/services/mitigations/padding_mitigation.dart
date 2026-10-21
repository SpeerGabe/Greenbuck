/*
  padding mitigation scheme. Every request goes out at the same size:
  - shapeBody: pads the plaintext JSON to plaintextTargetBytes before encryption (filler in a "_pad" key)
  - padWireBody: pads the final body (plaintext or encrypted envelope) to wireTargetBytes (filler in a "_wpad" key)
  - headerPad: X-Pad header value that makes the request line's method + path, the Authorization
    header and the X-Pad header add up to headerBudgetBytes
  The server ignores both keys and the header, and pads its responses the same way.
*/


import 'dart:convert';
import 'mitigation_scheme.dart';

class PaddingMitigation extends MitigationScheme {
  static const int plaintextTargetBytes = 2048; // mirrors PADDING_PLAINTEXT_BYTES in api/main.py
  static const int wireTargetBytes = 4096; // mirrors PADDING_TARGET_BYTES in api/main.py
  static const int headerBudgetBytes = 512;

  @override
  String get name => 'padding';

  @override
  bool get padRequests => true;

  @override
  String shapeBody(String plaintextJson) => padJson(plaintextJson, plaintextTargetBytes, '_pad');

  @override
  String padWireBody(String body) => padJson(body, wireTargetBytes, '_wpad');

  @override
  String headerPad({required String method, required String path, String? authorization}) {
    // header lines are "Name: value\r\n"
    final authLine = authorization == null ? 0 : 'Authorization: '.length + authorization.length + 2;
    final padLine = 'X-Pad: '.length + 2;
    final padLength = headerBudgetBytes - method.length - path.length - authLine - padLine;
    return 'x' * (padLength > 1 ? padLength : 1);
  }
}

// Splits a JSON object into the part kept before the filler, and the text that goes
// before and after the filler, so kept + prefix + filler + suffix is the same object
// with a [key] field holding the filler.
(String, String, String) _fillerParts(String json, String key) {
  if (json == '{}') return ('', '{"$key":"', '"}');
  return (json.substring(0, json.length - 1), ',"$key":"', '"}');
}

// Adds a [key] field holding [n] filler bytes to a JSON object.
// Returns the input unchanged if it isn't a JSON object or n <= 0.
// Same algorithm as _insert_filler() in api/main.py.
String insertFiller(String json, int n, String key) {
  if (!json.endsWith('}') || n <= 0) return json;
  final (kept, prefix, suffix) = _fillerParts(json, key);
  return '$kept$prefix${'x' * n}$suffix';
}

// Adds a [key] filler field to a JSON object so the result is exactly targetBytes (UTF-8).
// Returns the input unchanged if it isn't a JSON object or is already too long.
// Same algorithm as _pad_json() in api/main.py.
String padJson(String json, int targetBytes, String key) {
  if (!json.endsWith('}')) return json;
  final (kept, prefix, suffix) = _fillerParts(json, key);
  final n = targetBytes - utf8.encode(kept).length - prefix.length - suffix.length;
  return insertFiller(json, n, key);
}
