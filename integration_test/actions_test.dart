// Looped integration test for the six GreenBuck research actions.
// Runs every action in SCHEDULE in one app session. Each iteration remounts the
// app logged out on the login screen, performs one action through UI taps
// (register calls the API directly), and prints one GB_ITER line with the result.
// Configured with --dart-define values passed by capture/run_capture.py.

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:greenbuck/main.dart' as app;
import 'package:greenbuck/screens/transactions_screen.dart';
import 'package:greenbuck/services/api_service.dart';

// One character per action in SCHEDULE.
const Map<String, String> actionCodes = {
  'L': 'login',
  'O': 'logout',
  'R': 'register',
  'H': 'view_history',
  'T': 'make_transfer',
  'B': 'check_balance',
};

const String schedule = String.fromEnvironment('SCHEDULE', defaultValue: 'H');
const String encryption = String.fromEnvironment('ENCRYPTION', defaultValue: 'none');
const String mitigation = String.fromEnvironment('MITIGATION', defaultValue: 'none');
const String platform = String.fromEnvironment('PLATFORM', defaultValue: 'android');

// Pause after each step and before each iteration's first request. Longer than the
// client's 500 ms connection idle timeout, so every step starts on a fresh connection.
const Duration think = Duration(milliseconds: int.fromEnvironment('THINK_MS', defaultValue: 2000));

const Duration pollInterval = Duration(milliseconds: 100);
const Duration stepTimeout = Duration(seconds: 15);

// Pause after a failed iteration before remounting. Longer than the client's 5 s
// request timeout, so requests still in flight finish while their screen is mounted.
const Duration recoveryHold = Duration(seconds: 6);

class StepFailure implements Exception {
  StepFailure(this.message);
  final String message;

  @override
  String toString() => message;
}

Finder inTransactions(Finder finder) =>
    find.descendant(of: find.byType(TransactionsScreen), matching: finder);

// Pumps frames for [duration] of real time.
Future<void> hold(WidgetTester tester, Duration duration) async {
  final end = DateTime.now().add(duration);
  while (DateTime.now().isBefore(end)) {
    await tester.pump(pollInterval);
  }
}

// Pumps frames until [success] matches. Throws a StepFailure named by the key of
// the first entry in [failures] that matches instead, or on timeout.
Future<void> waitFor(
  WidgetTester tester,
  Finder success, {
  required String what,
  Map<String, Finder> failures = const <String, Finder>{},
}) async {
  final end = DateTime.now().add(stepTimeout);
  while (true) {
    if (success.evaluate().isNotEmpty) return;
    for (final entry in failures.entries) {
      if (entry.value.evaluate().isNotEmpty) throw StepFailure(entry.key);
    }
    if (DateTime.now().isAfter(end)) {
      throw StepFailure('timed out waiting for $what');
    }
    await tester.pump(pollInterval);
  }
}

// Taps Login and waits for the dashboard's balance and recent transactions to load.
Future<void> loginToDashboard(WidgetTester tester) async {
  await tester.tap(find.text('Login'));
  await waitFor(tester, find.text('Total Spent'), what: 'dashboard', failures: {
    'login failed': find.text('Login failed'),
    'dashboard failed to load': find.text('Could not load dashboard'),
  });
  await hold(tester, think);
}

// Opens the Transactions tab and waits for the list to load.
Future<void> openTransactions(WidgetTester tester) async {
  await tester.tap(find.text('Transactions'));
  await waitFor(tester, inTransactions(find.byType(ListTile)), what: 'transaction list', failures: {
    'transactions failed to load': find.text('Could not load transactions'),
    'transaction list is empty': inTransactions(find.text('No transactions yet.')),
  });
  await hold(tester, think);
}

// Performs one research action, starting from the login screen.
// [amount] is the whole-dollar amount used by make_transfer.
Future<void> performAction(WidgetTester tester, ApiService api, String action, int amount) async {
  switch (action) {
    case 'login':
      await loginToDashboard(tester);

    case 'view_history':
      await loginToDashboard(tester);
      await openTransactions(tester);

    case 'make_transfer':
      await loginToDashboard(tester);
      await openTransactions(tester);
      await tester.tap(find.byIcon(Icons.add));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField).first, '$amount.00');
      await tester.tap(find.text('Add Transaction').last);
      await waitFor(tester, inTransactions(find.text('-\$$amount.00')), what: 'new transaction', failures: {
        'transfer failed': find.text('Failed to add transaction'),
      });
      await hold(tester, think);

    case 'check_balance':
      await loginToDashboard(tester);
      await tester.tap(find.byIcon(Icons.refresh).first);
      await hold(tester, think);
      await waitFor(tester, find.text('Total Spent'), what: 'dashboard', failures: {
        'dashboard failed to load': find.text('Could not load dashboard'),
      });

    case 'register':
      await api.register('user_${DateTime.now().millisecondsSinceEpoch}', 'testpass');
      await hold(tester, think);

    case 'logout':
      await loginToDashboard(tester);
      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byType(TextField).first, '4242');
      await tester.tap(find.text('Unlock'));
      await tester.pumpAndSettle();
      await tester.dragUntilVisible(
        find.text('Log Out'),
        find.byType(ListView),
        const Offset(0, -100),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.text('Log Out'));
      await waitFor(tester, find.text('Login'), what: 'login screen');
      await hold(tester, think);

    default:
      throw StepFailure('unknown action: $action');
  }
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('Research schedule: ${schedule.length} iterations', (tester) async {
    final api = ApiService();
    api.encryption = encryption;
    api.mitigation = mitigation;
    api.platform = platform;
    api.mode = encryption == 'none' ? 'systemA' : 'systemB';

    var failures = 0;
    var transfers = 0;

    for (var i = 0; i < schedule.length; i++) {
      final action = actionCodes[schedule[i]] ?? schedule[i];
      // Whole-dollar amounts keep every transfer's JSON the same length; a different
      // amount per transfer lets the test find the new row in the list.
      final amount = 10 + transfers % 90;
      if (action == 'make_transfer') transfers++;

      final started = DateTime.now();
      String? error;
      try {
        api.authToken = null;
        await tester.pumpWidget(app.GreenBuckApp(key: UniqueKey()));
        await waitFor(tester, find.text('Login'), what: 'login screen');
        await hold(tester, think);
        await performAction(tester, api, action, amount);
      } catch (e) {
        error = e.toString().replaceAll('\n', ' ');
        if (error.length > 200) error = error.substring(0, 200);
        failures++;
        await hold(tester, recoveryHold);
      }

      final record = {
        'i': i,
        'action': action,
        'ok': error == null,
        'error': error,
        'device_start': started.toIso8601String(),
        'elapsed_ms': DateTime.now().difference(started).inMilliseconds,
      };
      debugPrint('GB_ITER ${jsonEncode(record)}');
    }

    await hold(tester, think);
    if (failures > 0) {
      fail('$failures of ${schedule.length} iterations failed');
    }
  }, timeout: Timeout.none);
}
