import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import '../models/transaction.dart';

class ApiService {
  // Singleton — shared state across every screen.
  static final ApiService _instance = ApiService._internal();
  factory ApiService() => _instance;
  ApiService._internal();

  static const String baseUrl = 'http://192.168.1.100:8000';

  // Research config — will be controlled by Settings screen later.
  // For now defaults to System A with no encryption or mitigation.
  String mode = 'systemA';
  String encryption = 'none';
  String mitigation = 'none';
  String platform = 'android';

  // Build the research headers sent with every request.
  // X-Request-ID is generated per request for capture linkage.
  Map<String, String> _headers({String? action}) {
    return {
      'Content-Type': 'application/json',
      'X-Request-ID': DateTime.now().millisecondsSinceEpoch.toString(),
      'X-Action': action ?? 'unknown',
      'X-Mode': mode,
      'X-Encryption': encryption,
      'X-Mitigation': mitigation,
      'X-Platform': platform,
    };
  }

  // Fetch all transactions from the backend.
  Future<List<Transaction>> getTransactions() async {
    final response = await http
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
    final response = await http
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
}