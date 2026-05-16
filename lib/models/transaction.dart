class Transaction {
  final int? id;
  final double amount;
  final String category;
  final String timestamp;
  final String? merchant;

  Transaction({
    this.id,
    required this.amount,
    required this.category,
    required this.timestamp,
    this.merchant,
  });

  // Parses a transaction from a backend JSON response.
  // ID comes back as an int from PostgreSQL's SERIAL primary key.
  factory Transaction.fromJson(Map<String, dynamic> json) {
    return Transaction(
      id: json['id'] as int?,
      amount: (json['amount'] as num).toDouble(),
      category: json['category'] as String,
      timestamp: json['timestamp'] as String,
      merchant: json['merchant'] as String?,
    );
  }

  // Converts a transaction to JSON for POST requests.
  // ID is omitted — the backend generates it.
  Map<String, dynamic> toJson() {
    return {
      'amount': amount,
      'category': category,
      'timestamp': timestamp,
      'merchant': merchant,
    };
  }
}