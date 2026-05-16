// Dashboard — calculates and shows real balance from backend data.

import 'package:flutter/material.dart';
import '../models/transaction.dart';
import '../services/api_service.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});

  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  final ApiService _apiService = ApiService();

  List<Transaction> _transactions = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadTransactions();
  }

  Future<void> _loadTransactions() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final transactions = await _apiService.getTransactions();
      setState(() {
        _transactions = transactions;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = 'Could not load dashboard';
        _loading = false;
      });
      debugPrint('Dashboard load failed: $e');
    }
  }

  // Sum of all transactions — placeholder balance calculation.
  double get _totalSpent =>
      _transactions.fold(0.0, (sum, t) => sum + t.amount);

  // Top 3 most recent transactions for the dashboard preview.
  List<Transaction> get _recent => _transactions.take(3).toList();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('GreenBuck'),
        backgroundColor: Colors.green,
        foregroundColor: Colors.white,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadTransactions,
          ),
        ],
      ),
      body: RefreshIndicator(
        color: Colors.green,
        onRefresh: _loadTransactions,
        child: _buildBody(),
      ),
    );
  }

  Widget _buildBody() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: Colors.green));
    }
    if (_error != null) {
      return ListView(
        children: [
          const SizedBox(height: 80),
          Center(child: Text(_error!, style: const TextStyle(color: Colors.grey))),
          const SizedBox(height: 12),
          Center(
            child: TextButton(
              onPressed: _loadTransactions,
              child: const Text('Retry'),
            ),
          ),
        ],
      );
    }

    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Total spent card
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: Colors.green,
            borderRadius: BorderRadius.circular(12),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Total Spent',
                style: TextStyle(fontSize: 14, color: Colors.white70)),
              const SizedBox(height: 4),
              Text(
                '\$${_totalSpent.toStringAsFixed(2)}',
                style: const TextStyle(
                  fontSize: 40,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
              const SizedBox(height: 4),
              Text(
                '${_transactions.length} transactions',
                style: const TextStyle(fontSize: 12, color: Colors.white70),
              ),
            ],
          ),
        ),
        const SizedBox(height: 24),
        const Text('Recent Transactions',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
        const SizedBox(height: 8),
        if (_recent.isEmpty)
          const Padding(
            padding: EdgeInsets.symmetric(vertical: 24),
            child: Center(
              child: Text('No transactions yet.',
                style: TextStyle(color: Colors.grey)),
            ),
          )
        else
          ..._recent.map((t) => Card(
                margin: const EdgeInsets.only(bottom: 8),
                child: ListTile(
                  leading: const CircleAvatar(
                    backgroundColor: Colors.green,
                    child: Icon(Icons.attach_money, color: Colors.white),
                  ),
                  title: Text(t.merchant ?? t.category),
                  subtitle: Text('${t.category} · ${t.timestamp}'),
                  trailing: Text(
                    '-\$${t.amount.toStringAsFixed(2)}',
                    style: const TextStyle(
                      color: Colors.red,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              )),
      ],
    );
  }
}