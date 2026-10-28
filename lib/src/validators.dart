import 'dart:convert';

import 'enums.dart';
import 'helpers.dart';

// Only the outer domain repetition may consume dots. Allowing dots inside a
// label creates exponentially many partitions when a long domain fails.
var _email = RegExp(
    r"^((([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+(\.([a-z]|\d|[!#\$%&'\*\+\-\/=\?\^_`{\|}~]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])+)*)|((\x22)((((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(([\x01-\x08\x0b\x0c\x0e-\x1f\x7f]|\x21|[\x23-\x5b]|[\x5d-\x7e]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(\\([\x01-\x09\x0b\x0c\x0d-\x7f]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF]))))*(((\x20|\x09)*(\x0d\x0a))?(\x20|\x09)+)?(\x22)))@((([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|\d|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))\.)+(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])|(([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])([a-z]|\d|-|_|~|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])*([a-z]|[\u00A0-\uD7FF\uF900-\uFDCF\uFDF0-\uFFEF])))$");

var _ipv4Maybe = RegExp(r'^(\d?\d?\d)\.(\d?\d?\d)\.(\d?\d?\d)\.(\d?\d?\d)$');

var _surrogatePairsRegExp = RegExp(r'[\uD800-\uDBFF][\uDC00-\uDFFF]');

var _alpha = RegExp(r'^[a-zA-Z]+$');
var _alphanumeric = RegExp(r'^[a-zA-Z0-9]+$');
var _numeric = RegExp(r'^-?[0-9]+$');
var _int = RegExp(r'^(?:-?(?:0|[1-9][0-9]*))$');
var _float =
    RegExp(r'^(?:-?(?:[0-9]+))?(?:\.[0-9]*)?(?:[eE][\+\-]?(?:[0-9]+))?$');
var _hexadecimal = RegExp(r'^[0-9a-fA-F]+$');
var _hexcolor = RegExp(r'^#?([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$');

var _base64 = RegExp(
    r'^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{4})$');

var _creditCard = RegExp(
    r'^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})$');

var _isbn10Maybe = RegExp(r'^(?:[0-9]{9}X|[0-9]{10})$');
var _isbn13Maybe = RegExp(r'^(?:[0-9]{13})$');

var _uuid = {
  UUIDVersion.uuidV3: RegExp(
      r'^[0-9A-F]{8}-[0-9A-F]{4}-3[0-9A-F]{3}-[0-9A-F]{4}-[0-9A-F]{12}$'),
  UUIDVersion.uuidV4: RegExp(
      r'^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$'),
  UUIDVersion.uuidV5: RegExp(
      r'^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$'),
  UUIDVersion.any:
      RegExp(r'^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$')
};

var _multibyte = RegExp(r'[^\x00-\x7F]');
var _ascii = RegExp(r'^[\x00-\x7F]+$');
var _fullWidth =
    RegExp(r'[^\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]');
var _halfWidth =
    RegExp(r'[\u0020-\u007E\uFF61-\uFF9F\uFFA0-\uFFDC\uFFE8-\uFFEE0-9a-zA-Z]');

/// check if the string matches the comparison
bool equals(String str, Object comparison) => str == comparison.toString();

/// check if the string contains the seed
bool contains(String str, Object seed) => str.contains(seed.toString());

/// check if string [str] matches the [pattern].
bool matches(String str, String pattern) {
  final re = RegExp(pattern);
  return re.hasMatch(str);
}

/// check if the string [str] is an email
bool isEmail(String str) => _email.hasMatch(str.toLowerCase());

/// check if the string [str] is a URL
///
/// * [protocols] sets the list of allowed protocols
/// * [requireTld] sets if TLD is required
/// * [requireProtocol] is a `bool` that sets if protocol is
///     required for validation
/// * [allowUnderscore] sets if underscores are allowed
/// * [hostWhitelist] sets the list of allowed hosts
/// * [hostBlacklist] sets the list of disallowed hosts
///
/// When either host list is nonempty, [str] must be an absolute URL with an
/// explicit `http://`, `https://` or `ftp://` scheme, even if [requireProtocol]
/// is false. The scheme must also be allowed by [protocols]. With both lists
/// empty, [requireProtocol] and [protocols] retain their usual behavior.
///
/// Host lists compare only hostnames, case-insensitively; ports are ignored.
/// With a nonempty list, URL hosts must use ASCII spelling, and numeric IPv4
/// spellings must be canonical dotted decimal (four octets, no leading zeros).
/// Supply canonical ASCII hostnames in both lists, such as `example.com`,
/// `xn--bcher-kva.com` or `127.0.0.1`, without schemes, ports or paths. List
/// entries are only lowercased: IDNA and IPv4 alias normalization is not
/// performed, so Unicode or numeric-alias entries do not match their canonical
/// equivalents.
bool isURL(String? str,
    {List<String?> protocols = const ['http', 'https', 'ftp'],
    bool requireTld = true,
    bool requireProtocol = false,
    bool allowUnderscore = false,
    List<String> hostWhitelist = const [],
    List<String> hostBlacklist = const []}) {
  // Browsers can treat a backslash as a slash, changing the parsed authority.
  if (str == null ||
      str.isEmpty ||
      str.length > 2083 ||
      str.contains(r'\') ||
      str.startsWith('mailto:')) {
    return false;
  }

  String protocol;
  String auth;
  String host;
  String hostname;
  int port;
  String portStr;
  String path;
  String query;
  String hash;
  List<String> split;

  final hasHostLists = hostWhitelist.isNotEmpty || hostBlacklist.isNotEmpty;

  // Host policies require an absolute URL with a supported authority scheme.
  split = str.split('://');
  if (split.length > 1) {
    protocol = shift(split);
    if (!protocols.contains(protocol) ||
        (hasHostLists && !const ['http', 'https', 'ftp'].contains(protocol))) {
      return false;
    }
  } else if (requireProtocol || hasHostLists) {
    return false;
  }
  str = split.join('://');

  // check hash
  split = str.split('#');
  str = shift(split);
  hash = split.join('#');
  if (hash != '' && RegExp(r'\s').hasMatch(hash)) {
    return false;
  }

  // check query params
  split = str.split('?');
  str = shift(split);
  query = split.join('?');
  if (query != '' && RegExp(r'\s').hasMatch(query)) {
    return false;
  }

  // check path
  split = str.split('/');
  str = shift(split);
  path = split.join('/');
  if (path != '' && RegExp(r'\s').hasMatch(path)) {
    return false;
  }

  // check auth type urls
  split = str.split('@');
  if (split.length > 1) {
    auth = shift(split);
    if (RegExp(r'\s').hasMatch(auth) || auth.startsWith(':')) {
      return false;
    }
  }

  // check hostname
  hostname = split.join('@');
  split = hostname.split(':');
  host = shift(split);
  if (hasHostLists && !_isUnambiguousListHost(host)) {
    return false;
  }
  host = host.toLowerCase();
  if (split.isNotEmpty) {
    portStr = split.join(':');
    try {
      port = int.parse(portStr, radix: 10);
    } on FormatException {
      return false;
    }
    if (!RegExp(r'^[0-9]+$').hasMatch(portStr) || port <= 0 || port > 65535) {
      return false;
    }
  }

  if (!isIP(host) &&
      !isFQDN(host,
          requireTld: requireTld, allowUnderscores: allowUnderscore) &&
      host != 'localhost') {
    return false;
  }

  if (hostWhitelist.isNotEmpty &&
      !hostWhitelist.any((allowed) => allowed.toLowerCase() == host)) {
    return false;
  }

  if (hostBlacklist.any((blocked) => blocked.toLowerCase() == host)) {
    return false;
  }

  return true;
}

bool _isUnambiguousListHost(String host) {
  // Check the original spelling: Unicode case folding can produce ASCII.
  if (_multibyte.hasMatch(host)) {
    return false;
  }
  // Browsers accept one to four decimal, octal or hexadecimal IPv4 components.
  // Reject numeric spellings conservatively, even if they overflow or are
  // invalid in a browser, unless already canonical dotted decimal IPv4.
  final numericHost = RegExp(
      r'^(?:[0-9]+|0x[0-9a-f]*)(?:\.(?:[0-9]+|0x[0-9a-f]*))*$',
      caseSensitive: false);
  if (!numericHost.hasMatch(host)) {
    return true;
  }
  return isIP(host, version: IPVersion.ipV4) &&
      host
          .split('.')
          .every((part) => part.length == 1 || !part.startsWith('0'));
}

/// check if the string [str] is IP [version] 4 or 6
///
/// * [version] selects IPv4, IPv6, or either version.
bool isIP(String? str, {IPVersion version = IPVersion.any}) {
  if (str == null) {
    return false;
  }
  if (version == IPVersion.any) {
    return isIP(str, version: IPVersion.ipV4) ||
        isIP(str, version: IPVersion.ipV6);
  } else if (version == IPVersion.ipV4) {
    if (!_ipv4Maybe.hasMatch(str)) {
      return false;
    }
    final parts = str.split('.')..sort((a, b) => int.parse(a) - int.parse(b));
    return int.parse(parts[3]) <= 255;
  }
  return version == IPVersion.ipV6 && _isIPv6(str);
}

bool _isIPv6(String str) {
  // A dotted decimal tail occupies two of the eight 16-bit groups.
  if (str.contains('.')) {
    final separator = str.lastIndexOf(':');
    if (separator < 0) {
      return false;
    }
    final octets = str.substring(separator + 1).split('.');
    if (octets.length != 4) {
      return false;
    }
    for (final octet in octets) {
      if (octet.isEmpty ||
          octet.length > 3 ||
          (octet.length > 1 && octet.startsWith('0')) ||
          octet.codeUnits.any((c) => c < 48 || c > 57) ||
          int.parse(octet) > 255) {
        return false;
      }
    }
    str = '${str.substring(0, separator + 1)}0:0';
  }

  final halves = str.split('::');
  if (halves.length > 2) {
    return false;
  }
  var groups = 0;
  for (final half in halves) {
    if (half.isEmpty && halves.length == 2) {
      continue;
    }
    for (final group in half.split(':')) {
      if (group.isEmpty || group.length > 4) {
        return false;
      }
      for (final c in group.codeUnits) {
        if (!(c >= 48 && c <= 57) &&
            !(c >= 65 && c <= 70) &&
            !(c >= 97 && c <= 102)) {
          return false;
        }
      }
      groups++;
    }
  }
  // Compression must replace at least one group, and may occur only once.
  return halves.length == 2 ? groups < 8 : groups == 8;
}

/// check if the string [str] is a fully qualified
/// domain name (e.g. domain.com).
///
/// * [requireTld] sets if TLD is required
/// * [allowUnderscores] sets if underscores are allowed
bool isFQDN(String str,
    {bool requireTld = true, bool allowUnderscores = false}) {
  final parts = str.split('.');
  if (parts.any((part) => part.isEmpty || part.length > 63) ||
      RegExp(r'\s').hasMatch(str)) {
    return false;
  }
  if (requireTld) {
    final tld = parts.removeLast();
    if (parts.isEmpty || !RegExp(r'^[a-zA-Z]{2,}$').hasMatch(tld)) {
      return false;
    }
  }

  final labelPattern = allowUnderscores
      ? RegExp(r'^[a-zA-Z\u00a1-\uffff0-9_-]+$')
      : RegExp(r'^[a-zA-Z\u00a1-\uffff0-9-]+$');
  for (final part in parts) {
    if (allowUnderscores) {
      if (part.contains('__')) {
        return false;
      }
    }
    if (!labelPattern.hasMatch(part)) {
      return false;
    }
    if (part[0] == '-' ||
        part[part.length - 1] == '-' ||
        part.contains('---')) {
      return false;
    }
  }
  return true;
}

/// check if the string [str] contains only letters (a-zA-Z).
bool isAlpha(String str) => _alpha.hasMatch(str);

/// check if the string [str] contains only numbers
bool isNumeric(String str) => _numeric.hasMatch(str);

/// check if the string [str] contains only letters and numbers
bool isAlphanumeric(String str) => _alphanumeric.hasMatch(str);

/// check if a string [str] is base64 encoded
bool isBase64(String str) => _base64.hasMatch(str);

/// check if the string [str] is an integer
bool isInt(String str) => _int.hasMatch(str);

/// check if the string [str] is a float
bool isFloat(String str) => _float.hasMatch(str);

/// check if the string  [str]is a hexadecimal number
bool isHexadecimal(String str) => _hexadecimal.hasMatch(str);

/// check if the string [str] is a hexadecimal color
bool isHexColor(String str) => _hexcolor.hasMatch(str);

/// check if the string [str] is lowercase
bool isLowercase(String str) => str == str.toLowerCase();

/// check if the string [str] is uppercase
bool isUppercase(String str) => str == str.toUpperCase();

/// check if the string [str] is a number that's divisible by another
///
/// [n] is a String or an int.
bool isDivisibleBy(String str, Object n) {
  try {
    return double.parse(str) % int.parse(n.toString()) == 0;
  } on FormatException {
    return false;
  }
}

/// check if the string [str] is null
bool isNull(String? str) => str == null || str.isEmpty;

/// check if the length of the string [str] falls in a range
bool isLength(String str, int min, [int? max]) {
  final surrogatePairs = _surrogatePairsRegExp.allMatches(str).toList();
  final len = str.length - surrogatePairs.length;
  return len >= min && (max == null || len <= max);
}

/// check if the string's length (in bytes) falls in a range.
bool isByteLength(String str, int min, [int? max]) =>
    str.length >= min && (max == null || str.length <= max);

/// check if the string is a UUID (version 3, 4 or 5).
bool isUUID(String? str, {UUIDVersion version = UUIDVersion.any}) {
  final pat = _uuid[version];
  return pat != null && pat.hasMatch(str!.toUpperCase());
}

/// check if the string is a date
bool isDate(String str) {
  try {
    DateTime.parse(str);
    return true;
  } on FormatException {
    return false;
  }
}

/// check if the string is a date that's after the specified date
///
/// If `date` is not passed, it defaults to now.
bool isAfter(String? str, [String? date]) {
  date ??= '${DateTime.now()}';

  DateTime strCompare;
  try {
    strCompare = DateTime.parse(date);
  } on FormatException {
    return false;
  }

  DateTime strDate;
  try {
    strDate = DateTime.parse(str!);
  } on FormatException {
    return false;
  }

  return strDate.isAfter(strCompare);
}

/// check if the string is a date that's before the specified date
///
/// If `date` is not passed, it defaults to now.
bool isBefore(String? str, [String? date]) {
  date ??= '${DateTime.now()}';

  DateTime strCompare;
  try {
    strCompare = DateTime.parse(date);
  } on FormatException {
    return false;
  }

  DateTime strDate;
  try {
    strDate = DateTime.parse(str!);
  } on FormatException {
    return false;
  }

  return strDate.isBefore(strCompare);
}

/// check if the string is in a array of allowed values
bool? isIn(String str, List<Object> values) {
  if (values.isEmpty) {
    return false;
  }

  // convert each value to a String
  values = values.map((e) => e.toString()).toList();

  return values.contains(str);
}

/// check if the string is a credit card
bool isCreditCard(String str) {
  final sanitized = str.replaceAll(RegExp('[^0-9]+'), '');
  if (!_creditCard.hasMatch(sanitized)) {
    return false;
  }

  // Luhn algorithm
  var sum = 0;
  String digit;
  var shouldDouble = false;

  for (var i = sanitized.length - 1; i >= 0; i--) {
    digit = sanitized.substring(i, i + 1);
    var tmpNum = int.parse(digit);

    if (shouldDouble) {
      tmpNum *= 2;
      if (tmpNum >= 10) {
        sum += (tmpNum % 10) + 1;
      } else {
        sum += tmpNum;
      }
    } else {
      sum += tmpNum;
    }
    shouldDouble = !shouldDouble;
  }

  return sum % 10 == 0;
}

/// check if the string is an ISBN (version 10 or 13)
bool isISBN(String? str, {ISBNVersion version = ISBNVersion.any}) {
  if (version == ISBNVersion.any) {
    return isISBN(str, version: ISBNVersion.isbn10) ||
        isISBN(str, version: ISBNVersion.isbn13);
  }

  final sanitized = str!.replaceAll(RegExp(r'[\s-]+'), '');
  var checksum = 0;

  if (version == ISBNVersion.isbn10) {
    if (!_isbn10Maybe.hasMatch(sanitized)) {
      return false;
    }
    for (var i = 0; i < 9; i++) {
      checksum += (i + 1) * int.parse(sanitized[i]);
    }
    if (sanitized[9] == 'X') {
      checksum += 10 * 10;
    } else {
      checksum += 10 * int.parse(sanitized[9]);
    }
    return checksum % 11 == 0;
  } else if (version == ISBNVersion.isbn13) {
    if (!_isbn13Maybe.hasMatch(sanitized)) {
      return false;
    }
    final factor = [1, 3];
    for (var i = 0; i < 12; i++) {
      checksum += factor[i % 2] * int.parse(sanitized[i]);
    }
    return int.parse(sanitized[12]) - ((10 - (checksum % 10)) % 10) == 0;
  }

  return false;
}

/// check if the string is valid JSON
bool isJSON(String str) {
  try {
    jsonDecode(str);
  } catch (e) {
    return false;
  }
  return true;
}

/// check if the string contains one or more multibyte chars
bool isMultibyte(String str) => _multibyte.hasMatch(str);

/// check if the string contains ASCII chars only
bool isAscii(String str) => _ascii.hasMatch(str);

/// check if the string contains any full-width chars
bool isFullWidth(String str) => _fullWidth.hasMatch(str);

/// check if the string contains any half-width chars
bool isHalfWidth(String str) => _halfWidth.hasMatch(str);

/// check if the string contains a mixture of full and half-width chars
bool isVariableWidth(String str) => isFullWidth(str) && isHalfWidth(str);

/// check if the string contains any surrogate pairs chars
bool isSurrogatePair(String str) => _surrogatePairsRegExp.hasMatch(str);

/// check if the string is a valid hex-encoded representation
/// of a MongoDB ObjectId
bool isMongoId(String str) => isHexadecimal(str) && str.length == 24;

var _threeDigit = RegExp(r'^\d{3}$');
var _fourDigit = RegExp(r'^\d{4}$');
var _fiveDigit = RegExp(r'^\d{5}$');
var _sixDigit = RegExp(r'^\d{6}$');
var _postalCodePatterns = {
  'AD': RegExp(r'^AD\d{3}$'),
  'AT': _fourDigit,
  'AU': _fourDigit,
  'BE': _fourDigit,
  'BG': _fourDigit,
  'CA': RegExp(
      r'^[ABCEGHJKLMNPRSTVXY]\d[ABCEGHJ-NPRSTV-Z][\s\-]?\d[ABCEGHJ-NPRSTV-Z]\d$',
      caseSensitive: false),
  'CH': _fourDigit,
  'CZ': RegExp(r'^\d{3}\s?\d{2}$'),
  'DE': _fiveDigit,
  'DK': _fourDigit,
  'DZ': _fiveDigit,
  'EE': _fiveDigit,
  'ES': _fiveDigit,
  'FI': _fiveDigit,
  'FR': RegExp(r'^\d{2}\s?\d{3}$'),
  'GB': RegExp(r'^(gir\s?0aa|[a-z]{1,2}\d[\da-z]?\s?(\d[a-z]{2})?)$',
      caseSensitive: false),
  'GR': RegExp(r'^\d{3}\s?\d{2}$'),
  'HR': RegExp(r'^([1-5]\d{4}$)'),
  'HU': _fourDigit,
  'ID': _fiveDigit,
  'IL': _fiveDigit,
  'IN': _sixDigit,
  'IS': _threeDigit,
  'IT': _fiveDigit,
  'JP': RegExp(r'^\d{3}\-\d{4}$'),
  'KE': _fiveDigit,
  'LI': RegExp(r'^(948[5-9]|949[0-7])$'),
  'LT': RegExp(r'^LT\-\d{5}$'),
  'LU': _fourDigit,
  'LV': RegExp(r'^LV\-\d{4}$'),
  'MX': _fiveDigit,
  'NL': RegExp(r'^\d{4}\s?[a-z]{2}$', caseSensitive: false),
  'NO': _fourDigit,
  'PL': RegExp(r'^\d{2}\-\d{3}$'),
  'PT': RegExp(r'^\d{4}\-\d{3}?$'),
  'RO': _sixDigit,
  'RU': _sixDigit,
  'SA': _fiveDigit,
  'SE': RegExp(r'^\d{3}\s?\d{2}$'),
  'SI': _fourDigit,
  'SK': RegExp(r'^\d{3}\s?\d{2}$'),
  'TN': _fourDigit,
  'TW': RegExp(r'^\d{3}(\d{2})?$'),
  'UA': _fiveDigit,
  'US': RegExp(r'^\d{5}(-\d{4})?$'),
  'ZA': _fourDigit,
  'ZM': _fiveDigit
};

bool isPostalCode(String? text, String locale, {bool Function()? orElse}) {
  final pattern = _postalCodePatterns[locale];
  return pattern != null
      ? pattern.hasMatch(text!)
      : orElse != null
          ? orElse()
          : throw const FormatException();
}
