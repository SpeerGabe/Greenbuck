// Smoke test: the app builds and opens on the login screen (no backend needed).

import 'package:flutter_test/flutter_test.dart';

import 'package:greenbuck/main.dart';

void main() {
  testWidgets('App starts on the login screen', (WidgetTester tester) async {
    await tester.pumpWidget(const GreenBuckApp());

    expect(find.text('GreenBuck'), findsOneWidget);
    expect(find.text('Login'), findsOneWidget);
    expect(find.text('Create Account'), findsOneWidget);
  });
}
