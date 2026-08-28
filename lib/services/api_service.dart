import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:http/io_client.dart';
import 'package:http/http.dart' as http;
import '../models/transaction.dart';

class ApiService {
  // Singleton — shared state across every screen.
  static final ApiService _instance = ApiService._internal();
  factory ApiService() => _instance;
  ApiService._internal();

  static const String baseUrl = 'https://192.168.1.100:8000';

  // Custom HTTP client that accepts the backend's self-signed certificate.
  // Research instrument on an isolated network — in production you would
  // use a CA-signed cert and never bypass verification.
  static final http.Client _client = IOClient(
    HttpClient()
      ..badCertificateCallback = ((cert, host, port) => true)
      ..maxConnectionsPerHost = 1
      ..idleTimeout = const Duration(milliseconds: 100),
  );

  // Research config — controlled by the Settings screen.
  String mode = 'systemA';
  String encryption = 'none';
  String mitigation = 'none';
  String platform = 'android';
  String? authToken;

  // Build the research headers sent with every request.
  // X-Request-ID is generated per request for capture linkage.
Map<String, String> _headers({String? action}) {
    final headers = {
      'Content-Type': 'application/json',
      'X-Request-ID': DateTime.now().millisecondsSinceEpoch.toString(),
      'X-Action': action ?? 'unknown',
      'X-Mode': mode,
      'X-Encryption': encryption,
      'X-Mitigation': mitigation,
      'X-Platform': platform,
    };
    // Attach the JWT on every request once logged in. Protected routes
    // (transactions, balance) require it; open routes ignore it.
    if (authToken != null) {
      headers['Authorization'] = 'Bearer $authToken';
    }
    return headers;
  }

  // Fetch all transactions from the backend.
  Future<List<Transaction>> getTransactions() async {
    final response = await _client
        .get(
          Uri.parse('$baseUrl/transactions'),
          headers: _headers(action: 'view_history'),
        )
        .timeout(const Duration(seconds: 5));

    if (response.statusCode == 200) {
      final Map<String, dynamic> body = jsonDecode(response.body);
      final List<dynamic> data = body['transactions'];
      return data.map((json) => Transaction.fromJson(json)).toList();
    } else {
      throw Exception('Failed to load transactions: ${response.statusCode}');
    }
  }

  // Create a new transaction. Returns the created record with its real ID.
  Future<Transaction> createTransaction(Transaction transaction) async {
    final response = await _client
        .post(
          Uri.parse('$baseUrl/transactions'),
          headers: _headers(action: 'make_transfer'),
          body: jsonEncode(transaction.toJson()),
        )
        .timeout(const Duration(seconds: 5));

    if (response.statusCode == 201) {
      return Transaction.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Failed to create transaction: ${response.statusCode}');
    }
  }

  // Login — produces a distinct POST pattern as a research action.
  Future<Map<String, dynamic>> login(String username, String password) async {
    final response = await _client
        .post(
          Uri.parse('$baseUrl/auth/login'),
          headers: _headers(action: 'login'),
          body: jsonEncode({'username': username, 'password': password}),
        )
        .timeout(const Duration(seconds: 5));

    if (response.statusCode == 200) {
      final body = jsonDecode(response.body);
      // Save the JWT so _headers() attaches it to subsequent requests.
      authToken = body['access_token'] as String?;
      return body;
    } else {
      throw Exception('Login failed: ${response.statusCode}');
    }
  }

  // Register a new user — captured research action (6th class).
  Future<void> register(String username, String password) async {
    final response = await _client
        .post(
          Uri.parse('$baseUrl/auth/register'),
          headers: _headers(action: 'register'),
          body: jsonEncode({'username': username, 'password': password}),
        )
        .timeout(const Duration(seconds: 5));

    if (response.statusCode != 201) {
      throw Exception('Registration failed: ${response.statusCode}');
    }
  }

  // Logout — small response, distinct from other actions.
  Future<void> logout(String token) async {
    final response = await _client
        .post(
          Uri.parse('$baseUrl/auth/logout'),
          headers: _headers(action: 'logout'),
          body: jsonEncode({'token': token}),
        )
        .timeout(const Duration(seconds: 5));

    if (response.statusCode != 200) {
      throw Exception('Logout failed: ${response.statusCode}');
    }
  }

  // Balance summary — smaller response than full transactions list.
  Future<double> getBalance() async {
    final response = await _client
        .get(
          Uri.parse('$baseUrl/balance'),
          headers: _headers(action: 'check_balance'),
        )
        .timeout(const Duration(seconds: 5));

    if (response.statusCode == 200) {
      final body = jsonDecode(response.body);
      return (body['balance'] as num).toDouble();
    } else {
      throw Exception('Balance check failed: ${response.statusCode}');
    }
  }
}