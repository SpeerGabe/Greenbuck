import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:http/io_client.dart';
import 'package:http/http.dart' as http;
import '../models/transaction.dart';
import 'encryption_service.dart';
import 'mitigation_service.dart';
import 'request_batcher.dart';
import 'mitigations/batching_mitigation.dart';


class ApiService {
  // Singleton — shared state across every screen.
  static final ApiService _instance = ApiService._internal();
  factory ApiService() => _instance;
  ApiService._internal();

  static const String baseUrl = String.fromEnvironment(
  'BASE_URL',
  defaultValue: 'https://192.168.1.100:8000',
  );

  // Singleton instance of the EncryptionService for handling encryption and decryption.
  final EncryptionService encryptionService = EncryptionService();

  // Singleton instance of the MitigationService for handling mitigation schemes.
  final MitigationService mitigationService = MitigationService();

  // singleton instance of the request batcher
  late final RequestBatcher _batcher = RequestBatcher(
    windowMs: BatchingMitigation.windowMs,
    maxBatchSize: BatchingMitigation.maxBatchSize,
    sendBatch: _sendBatch,
  );

  // Custom HTTP client that accepts the backend's self-signed certificate.
  // Research instrument on an isolated network — in production you would
  // use a CA-signed cert and never bypass verification.
  static final http.Client _client = IOClient(
    HttpClient()
      ..badCertificateCallback = ((cert, host, port) => true)
      ..maxConnectionsPerHost = 1
      ..idleTimeout = const Duration(milliseconds: 500),
  );

  // Research config — controlled by the Settings screen.
  String mode = 'systemA';
  //mitigation and encryption are set to 'none' by default, but can be changed via the Settings screen.
  // setter and getter for mitigation and encryption are provided to update the active scheme in the respective services.
  String _encryption = 'none';
  String get encryption => _encryption;
  set encryption(String value) {
    encryptionService.setActiveScheme(value);
    _encryption = value;
  }
  String _mitigation = 'none';
  String get mitigation => _mitigation;
  set mitigation(String value) {
    mitigationService.setActiveScheme(value);
    _mitigation = value;
  }
  bool get _batching => mitigationService.activeScheme.batchRequests;
  String platform = 'android';
  String? authToken;

  // Capture run ID, passed in by run_capture.py via --dart-define=RUN_ID.
  // Same value on every request in one capture, so timing_log rows can be
  // joined to markers.jsonl. Manual app use falls back to 'manual'.
  static const String runId = String.fromEnvironment('RUN_ID', defaultValue: 'manual');

  static final Random _rng = Random.secure();

  // 128 random bits as 32 hex chars. Unique even when two requests fire in
  // the same millisecond (the dashboard's Future.wait), and always the same
  // length so it never changes the TLS record size.
  static String _newRequestId() {
    final sb = StringBuffer();
    for (var i = 0; i < 16; i++) {
      sb.write(_rng.nextInt(256).toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  // Research label headers are padded to this fixed width with '.' so a
  // label's length doesn't change the encrypted request size. The server
  // strips the padding (research_header() in api/main.py).
  static const int _labelWidth = 16;

  static String _label(String value) {
    assert(value.length <= _labelWidth,
        'research label "$value" is longer than $_labelWidth chars');
    return value.padRight(_labelWidth, '.');
  }

  // Build the research headers sent with every request.
  // X-Request-ID is generated per request for capture linkage.
  Map<String, String> _headers({String? action}) {
    final headers = {
      // charset set explicitly: package:http appends it to requests with a
      // body, so this keeps the header identical on every request.
      'Content-Type': 'application/json; charset=utf-8',
      'X-Request-ID': _newRequestId(),
      'X-Run-ID': runId,
      'X-Action': _label(action ?? 'unknown'),
      'X-Mode': _label(mode),
      'X-Encryption': _label(encryption),
      'X-Mitigation': _label(mitigation),
      'X-Platform': _label(platform),
    };
    // Attach the JWT on every request once logged in. Protected routes
    // (transactions, balance) require it; open routes ignore it.
    if (authToken != null) {
      headers['Authorization'] = 'Bearer $authToken';
    }
    return headers;
  }

  // builds a JSON body and applies the mitigation's padding
  String _plainBody(Map<String, dynamic> dataMap) {
    final jsonString = jsonEncode(dataMap);
    final shapedJson = mitigationService.activeScheme.shapeBody(jsonString);
    return shapedJson;
  }

  // prepare the request body, encrypting it if encryption is enabled.
  Future<String> _prepareRequestBody(Map<String, dynamic> dataMap) async {
    final shapedJson = _plainBody(dataMap);

    if (encryption == 'none') {
      return shapedJson;
    }

    final envelope = await encryptionService.encryptPayload(shapedJson);
    final encryptedBody = jsonEncode(envelope);
    return encryptedBody;
  }

  // Sends one request to [path].
  // [data] is the JSON body (null = no body). [encryptedRoute] marks routes
  // whose bodies use field-level encryption (everything except /auth/*).
  // Under padding, every request carries a body (GETs send an empty object),
  // the final body is padded to the same size, and an X-Pad header evens out
  // the request line and Authorization header, so all requests are the same
  // size on the wire.
  Future<http.Response> _send(
    String method,
    String path,
    String action, {
    Map<String, dynamic>? data,
    bool encryptedRoute = false,
  }) async {
    final scheme = mitigationService.activeScheme;
    final headers = _headers(action: action);

    if (scheme.padRequests) {
      data ??= {};
    }

    String? body;
    if (data != null) {
      body = encryptedRoute ? await _prepareRequestBody(data) : _plainBody(data);
    }

    if (scheme.padRequests) {
      body = scheme.padWireBody(body!);
      headers['X-Pad'] = scheme.headerPad(
        method: method,
        path: path,
        authorization: headers['Authorization'],
      );
    }

    final request = http.Request(method, Uri.parse('$baseUrl$path'))
      ..headers.addAll(headers);
    if (body != null) {
      request.body = body;
    }

    return _client
        .send(request)
        .then(http.Response.fromStream)
        .timeout(const Duration(seconds: 5));
  }

  Future<Map<String, dynamic>> _parseResponseBody(String responseBody) async {
    final decodedJson = jsonDecode(responseBody);

    if (encryption == 'none'){
      return decodedJson as Map<String, dynamic>;
    }

    final decryptedString = await encryptionService.decryptPayload(decodedJson as Map<String, dynamic>);
    final decryptedMap = jsonDecode(decryptedString) as Map<String, dynamic>;
    return decryptedMap;
  }


  // Fetch all transactions from the backend.
  Future<List<Transaction>> getTransactions() async {

    if(_batching) {
      final body = await _batcher.enqueue('view_history');
      final List<dynamic> data = body['transactions'];
      return data.map((json) => Transaction.fromJson(json)).toList();
    }

    final response = await _send('GET', '/transactions', 'view_history', encryptedRoute: true);

    if (response.statusCode == 200) {
      final body = await _parseResponseBody(response.body);
      final List<dynamic> data = body['transactions'];
      return data.map((json) => Transaction.fromJson(json)).toList();
    } else {
      throw Exception('Failed to load transactions: ${response.statusCode}');
    }
  }

  // Create a new transaction. Returns the created record with its real ID.
  Future<Transaction> createTransaction(Transaction transaction) async {
    if(_batching){
      final body = await _batcher.enqueue('make_transfer', transaction.toJson());
      return Transaction.fromJson(body);
    }

    final response = await _send(
      'POST', '/transactions', 'make_transfer',
      data: transaction.toJson(), encryptedRoute: true,
    );

    if (response.statusCode == 201) {
      final body = await _parseResponseBody(response.body);
      return Transaction.fromJson(body);
    } else {
      throw Exception('Failed to create transaction: ${response.statusCode}');
    }
  }

  // Login — produces a distinct POST pattern as a research action.
  Future<Map<String, dynamic>> login(String username, String password) async {
    final clientPubKey = await encryptionService.generateClientPublicKey();

    final response = await _send('POST', '/auth/login', 'login', data: {
      'username': username,
      'password': password,
      'client_public_key': clientPubKey,
    });

    if (response.statusCode == 200) {
      //parse the body for encryption
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      if (body.containsKey('server_public_key')) {
        await encryptionService.deriveSessionKeys(body['server_public_key'] as String);
      }

      authToken = body['access_token'] as String?;
      return body;
    } else {
      throw Exception('Login failed: ${response.statusCode}');
    }
  }

  // Register a new user — captured research action (6th class).
  Future<void> register(String username, String password) async {
    final response = await _send('POST', '/auth/register', 'register',
        data: {'username': username, 'password': password});

    if (response.statusCode != 201) {
      throw Exception('Registration failed: ${response.statusCode}');
    }
  }

  // Logout — small response, distinct from other actions.
  Future<void> logout(String token) async {
    final response = await _send('POST', '/auth/logout', 'logout', data: {'token': token});

    if (response.statusCode != 200) {
      throw Exception('Logout failed: ${response.statusCode}');
    }
  }

  // Balance summary — smaller response than full transactions list.
  Future<double> getBalance() async {
    if(_batching){
      final body = await _batcher.enqueue('check_balance');
      return (body['balance'] as num).toDouble();
    }

    final response = await _send('GET', '/balance', 'check_balance', encryptedRoute: true);

    if (response.statusCode == 200) {
      final body = await _parseResponseBody(response.body);
      return (body['balance'] as num).toDouble();
    } else {
      throw Exception('Balance check failed: ${response.statusCode}');
    }
  }

  // sends out a batch as a single POST and returns the per request results
  Future<List<dynamic>> _sendBatch(List<Map<String, dynamic>> items) async {
    final response = await _send('POST', '/batch', 'batch',
        data: {'requests': items}, encryptedRoute: true);

    if (response.statusCode != 200) {
      throw Exception('Batch failed: ${response.statusCode}');
    }

    final body = await _parseResponseBody(response.body);
    final responses = body['responses'] as List<dynamic>;
    return responses;
  }
}
