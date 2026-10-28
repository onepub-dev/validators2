@TestOn('vm')
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:test/test.dart';
import 'package:validators2/validators2.dart' as v;

void main() {
  // Run the synchronous regex in a separate process: a Future timeout alone
  // cannot interrupt catastrophic backtracking on the test runner's isolate.
  if (Platform.environment['VALIDATORS2_EMAIL_REGRESSION_WORKER'] == '1') {
    for (final labelCount in [64, 256]) {
      final labels = List.filled(labelCount, 'a').join('.');
      final cases = {
        'user@$labels.com': true,
        'user@$labels.': false,
        'user@$labels.com!': false,
        'user@$labels..com': false,
        'user@$labels.123': false,
      };
      for (final entry in cases.entries) {
        if (v.isEmail(entry.key) != entry.value) {
          stderr.writeln('Unexpected email result: ${entry.key}');
          exitCode = 1;
          return;
        }
      }
    }
    return;
  }

  test('IsEmail handles many short domain labels within a bounded time',
      () async {
    final process = await Process.start(
      Platform.resolvedExecutable,
      ['test/email_performance_test.dart'],
      environment: {'VALIDATORS2_EMAIL_REGRESSION_WORKER': '1'},
    );
    final stdoutResult = process.stdout.transform(utf8.decoder).join();
    final stderrResult = process.stderr.transform(utf8.decoder).join();
    try {
      final status = await process.exitCode.timeout(
        const Duration(seconds: 15),
        onTimeout: () => throw TimeoutException(
          'Email validation exceeded 15 seconds; possible regex backtracking.',
        ),
      );
      expect(status, 0, reason: '${await stdoutResult}${await stderrResult}');
    } finally {
      process.kill(ProcessSignal.sigkill);
      await process.exitCode.timeout(const Duration(seconds: 5));
      await Future.wait([stdoutResult, stderrResult])
          .timeout(const Duration(seconds: 5));
    }
  }, timeout: const Timeout(Duration(seconds: 30)));
}
