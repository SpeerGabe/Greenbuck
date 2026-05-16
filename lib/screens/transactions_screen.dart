import 'package:flutter/material.dart';
import '../models/transaction.dart';
import '../services/api_service.dart';

class TransactionsScreen extends StatefulWidget {
  const TransactionsScreen({super.key});

  @override
  State<TransactionsScreen> createState() => _TransactionsScreenState();
}

class _TransactionsScreenState extends State<TransactionsScreen> {
  // Real transactions fetched from the backend.
  List<Transaction> _transactions = [];
  bool _loading = true;
  String? _error;

  final _amountController = TextEditingController();
  final _merchantController = TextEditingController();
  final ApiService _apiService = ApiService();
  String _selectedCategory = 'Food';

  final List<String> _categories = [
    'Food', 'Bills', 'Entertainment', 'Gas', 'Groceries', 'Other'
  ];

  @override
  void initState() {
    super.initState();
    _loadTransactions();
  }

  // Fetch transactions from the backend.
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
        _error = 'Could not load transactions';
        _loading = false;
      });
      debugPrint('Load failed: $e');
    }
  }

  void _openAddForm() {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
      ),
      builder: (context) {
        return Padding(
          padding: EdgeInsets.only(
            left: 24, right: 24, top: 24,
            bottom: MediaQuery.of(context).viewInsets.bottom + 24,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text('Add Transaction',
                style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold)),
              const SizedBox(height: 16),
              TextField(
                controller: _amountController,
                keyboardType: TextInputType.number,
                decoration: const InputDecoration(
                  labelText: 'Amount',
                  prefixText: '\$',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              DropdownButtonFormField<String>(
                value: _selectedCategory,
                decoration: const InputDecoration(
                  labelText: 'Category',
                  border: OutlineInputBorder(),
                ),
                items: _categories
                    .map((c) => DropdownMenuItem(value: c, child: Text(c)))
                    .toList(),
                onChanged: (val) => setState(() => _selectedCategory = val!),
              ),
              const SizedBox(height: 12),
              TextField(
                controller: _merchantController,
                decoration: const InputDecoration(
                  labelText: 'Merchant (optional)',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.green,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                  onPressed: _submitTransaction,
                  child: const Text('Add Transaction',
                    style: TextStyle(fontSize: 16)),
                ),
              ),
            ],
          ),
        );
      },
    );
  }

  // Submit the form, POST to backend, then refresh the list from real data.
  void _submitTransaction() async {
    final amount = double.tryParse(_amountController.text);
    if (amount == null || amount <= 0) return;

    final newTransaction = Transaction(
      amount: amount,
      category: _selectedCategory,
      timestamp: DateTime.now().toIso8601String().split('T')[0],
      merchant: _merchantController.text.isEmpty
          ? null
          : _merchantController.text,
    );

    _amountController.clear();
    _merchantController.clear();
    Navigator.pop(context);

    try {
      // POST to backend — returns the created record with real ID.
      await _apiService.createTransaction(newTransaction);
      // Reload from backend so the list always matches the database.
      await _loadTransactions();
    } catch (e) {
      debugPrint('Create failed: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Failed to add transaction')),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Transactions'),
        backgroundColor: Colors.green,
        foregroundColor: Colors.white,
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _loadTransactions,
          ),
        ],
      ),
      body: _buildBody(),
      floatingActionButton: FloatingActionButton(
        onPressed: _openAddForm,
        backgroundColor: Colors.green,
        child: const Icon(Icons.add, color: Colors.white),
      ),
    );
  }

  Widget _buildBody() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: Colors.green));
    }
    if (_error != null) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Text(_error!, style: const TextStyle(color: Colors.grey)),
            const SizedBox(height: 8),
            TextButton(
              onPressed: _loadTransactions,
              child: const Text('Retry'),
            ),
          ],
        ),
      );
    }
    if (_transactions.isEmpty) {
      return const Center(
        child: Text('No transactions yet.', style: TextStyle(color: Colors.grey)),
      );
    }
    return RefreshIndicator(
      color: Colors.green,
      onRefresh: _loadTransactions,
      child: ListView.builder(
        itemCount: _transactions.length,
        itemBuilder: (context, index) {
          final t = _transactions[index];
          return ListTile(
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
          );
        },
      ),
    );
  }
}