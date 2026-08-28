// Flutter integration tests for the 5 GreenBuck research actions.
// Each test triggers one user action through real UI taps.
// Configured via environment variables passed by the capture script.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:greenbuck/main.dart' as app;
import 'package:greenbuck/services/api_service.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  const action = String.fromEnvironment('ACTION', defaultValue: 'view_history');
  const encryption = String.fromEnvironment('ENCRYPTION', defaultValue: 'none');
  const mitigation = String.fromEnvironment('MITIGATION', defaultValue: 'none');
  const platform = String.fromEnvironment('PLATFORM', defaultValue: 'android');

  testWidgets('Trigger research action: $action', (tester) async {
    final api = ApiService();
    api.encryption = encryption;
    api.mitigation = mitigation;
    api.platform = platform;
    api.mode = encryption == 'none' ? 'systemA' : 'systemB';

    app.main();
    await tester.pumpAndSettle(const Duration(seconds: 2));

    switch (action) {
      case 'login':
        await tester.tap(find.text('Login'));
        await tester.pumpAndSettle(const Duration(seconds: 4));
        break;

      case 'view_history':
        await tester.tap(find.text('Login'));
        await tester.pumpAndSettle(const Duration(seconds: 4));
        await tester.tap(find.text('Transactions'));
        await tester.pumpAndSettle(const Duration(seconds: 3));
        break;

      case 'make_transfer':
        await tester.tap(find.text('Login'));
        await tester.pumpAndSettle(const Duration(seconds: 4));
        await tester.tap(find.text('Transactions'));
        await tester.pumpAndSettle();
        await tester.tap(find.byIcon(Icons.add));
        await tester.pumpAndSettle();
        await tester.enterText(find.byType(TextField).first, '50.00');
        await tester.tap(find.text('Add Transaction').last);
        await tester.pumpAndSettle(const Duration(seconds: 3));
        break;

      case 'check_balance':
        await tester.tap(find.text('Login'));
        await tester.pumpAndSettle(const Duration(seconds: 4));
        await tester.tap(find.byIcon(Icons.refresh).first);
        await tester.pumpAndSettle(const Duration(seconds: 3));
        break;

      
      case 'register':
        // Unique username per run so every capture is a successful 201,
        // not a 409 "already exists" (which would be different traffic).
        final uniqueUser = 'user_${DateTime.now().millisecondsSinceEpoch}';
        await api.register(uniqueUser, 'testpass');
        await tester.pumpAndSettle(const Duration(seconds: 2));
        break;
        
      case 'logout':
        await tester.tap(find.text('Login'));
        await tester.pumpAndSettle(const Duration(seconds: 4));
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
        await tester.tap(find.text('Log Out'));
        await tester.pumpAndSettle(const Duration(seconds: 3));
        break;

      default:
        fail('Unknown action: $action');
    }

    // Brief hold so response packets land in the capture window.
    await tester.pumpAndSettle(const Duration(seconds: 2));
  });
}