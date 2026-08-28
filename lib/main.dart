import 'package:flutter/material.dart';
import 'screens/login_screen.dart';

void main() {
  runApp(const GreenBuckApp());
}

class GreenBuckApp extends StatelessWidget {
  const GreenBuckApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'GreenBuck',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.green),
        useMaterial3: true,
      ),
      home: const LoginScreen(),
    );
  }
}