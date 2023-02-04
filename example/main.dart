import 'package:validators2/sanitizers.dart';
import 'package:validators2/validators2.dart';

void main() {
  print(toString(1));
  print(trim('  hello '));
  print(toDouble('1.23'));

  print(isDate('1988-01-01'));
  print(isNumeric('123'));
  print(isAlphanumeric('abc123'));
  print('isUrl: ${isURL('example', requireTld: false)}');
}
