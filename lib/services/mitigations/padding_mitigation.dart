/*
  padding mitigation scheme, adds padding to traffic before encryption to make it harder to analyze traffic
  implements name and shapeBody methods from MitigationScheme
  - shapeBody: adds filler to the json, before the closing brace in a new key called _pad, the server will ignore this key when parsing the json
*/


import 'dart:convert';
import 'mitigation_scheme.dart';

class PaddingMitigation extends MitigationScheme {
  static const int targetBytes = 4096; // 4KB. mirrors the server sided padding mitigation scheme

  static const int _overheadBytes = 10; //net bytes the wrapper adds besides the filler

  @override
  String get name => 'padding';

  @override
  String shapeBody(String plaintextJson) {
    //measure utf8 bytes of the plaintext json, if it is less than 4kb, add filler to reach 4kb
    final currentBytes = utf8.encode(plaintextJson).length;
    final padLength = targetBytes - currentBytes - _overheadBytes;

    //if over or empty, return plaintext json
    final canPad = padLength > 0 && plaintextJson.endsWith('}') && plaintextJson != '{}';
    if (!canPad) {
      return plaintextJson;
    }

    final filler = 'x' * padLength;
    final withoutClosingBrace = plaintextJson.substring(0, plaintextJson.length -1);
    //add filler to the json, before the closing brace in a new key called _pad, the server will ignore this key when parsing the json
    final paddedJson = '$withoutClosingBrace,"_pad":"$filler"}'; 
    return paddedJson;
  }
}