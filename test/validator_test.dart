import 'package:test/test.dart';
import 'package:validators2/validators2.dart' as v;
import 'package:validators2/validators2.dart';

void check<T>({
  required bool? Function(T value) validator,
  List<T> valid = const [],
  List<T> invalid = const [],
}) {
  for (final v in valid) {
    expect(validator(v), true, reason: '"$v" should be valid');
  }
  for (final v in invalid) {
    expect(validator(v), false, reason: '"$v" should be invalid');
  }
}

void main() {
  test('equals', () {
    check<String>(
        validator: (val) => v.equals(val, 'abc'),
        valid: ['abc'],
        invalid: ['Abc', '123']);
  });

  test('contains', () {
    check<String>(
        validator: (val) => v.contains(val, 'foo'),
        valid: ['foo', 'foobar', 'bazfoo'],
        invalid: ['Foo', 'bar', '']);
  });

  test('Matches', () {
    check<String>(
        validator: (val) => v.matches(val, 'abc'),
        valid: ['abc', 'abcdef', '123abc'],
        invalid: ['acb', 'ABC']);
  });

  test('IsEmail', () {
    check<String>(validator: v.isEmail, valid: [
      'foo@bar.com',
      'x@x.x',
      'foo@bar.com.au',
      'foo+bar@bar.com',
      'hans.m端ller@test.com',
      'hans@m端ller.com',
      'test|123@m端ller.com',
      'test+ext@gmail.com',
      'some.name.midd.leNa.me.+extension@GoogleMail.com'
    ], invalid: [
      'invalidemail@',
      'invalid.com',
      '@invalid.com',
      'foo@bar.com.',
      'foo@bar.co.uk.'
    ]);
  });

  test('IsURL', () {
    check(validator: v.isURL, valid: [
      'foobar.com',
      'www.foobar.com',
      'foobar.com/',
      'valid.au',
      'http://www.foobar.com/',
      'http://www.foobar.com:23/',
      'http://www.foobar.com:65535/',
      'http://www.foobar.com:5/',
      'https://www.foobar.com/',
      'ftp://www.foobar.com/',
      'http://www.foobar.com/~foobar',
      'http://user:pass@www.foobar.com/',
      'http://127.0.0.1/',
      'http://10.0.0.0/',
      'http://10.0.0.0:3000/',
      'http://189.123.14.13/',
      'http://duckduckgo.com/?q=%2F',
      r"http://foobar.com/t$-_.+!*'(),",
      'http://localhost:3000/',
      'http://foobar.com/?foo=bar#baz=qux',
      'http://foobar.com?foo=bar',
      'http://foobar.com#baz=qux',
      'http://www.xn--froschgrn-x9a.net/',
      'http://xn--froschgrn-x9a.com/',
      'http://foo--bar.com'
    ], invalid: [
      'xyz://foobar.com',
      'invalid/',
      'invalid.x',
      'invalid.',
      '.com',
      'http://com/',
      'http://300.0.0.1/',
      'mailto:foo@bar.com',
      'rtmp://foobar.com',
      'http://www.xn--.com/',
      'http://xn--.com/',
      'http:// :pass@www.foobar.com/',
      'http://www.foobar.com:0/',
      'http://www.foobar.com:70000/',
      'http://www.foobar.com:99999/',
      'http://www.-foobar.com/',
      'http://www.foobar-.com/',
      'http://www.foo---bar.com/',
      'http://www.foo_bar.com/',
      '',
      'http://foobar.com/${List.filled(2083, 'f')}',
      'http://*.foo.com',
      '*.foo.com',
      '!.foo.com',
      'http://localhost:61500this is an invalid url!!!!'
    ]);

    expect(v.isURL('www.example.com', requireProtocol: true), false);
    expect(v.isURL('example', requireTld: false), true);

    expect(
        v.isURL('www.example.com', hostWhitelist: ['www.example.com']), true);
    expect(
        v.isURL('www.example.com', hostWhitelist: ['www.another.com']), false);

    expect(
        v.isURL('www.example.com', hostBlacklist: ['www.example.com']), false);
    expect(
        v.isURL('www.example.com', hostBlacklist: ['www.another.com']), true);
  });

  test('IsIP', () {
    check(validator: v.isIP, valid: [
      '127.0.0.1',
      '0.0.0.0',
      '255.255.255.255',
      '1.2.3.4',
      '::1',
      '2001:db8:0000:1:1:1:1:1'
    ], invalid: [
      'abc',
      '256.0.0.0',
      '0.0.0.256',
      '26.0.0.256'
    ]);
  });

  test('IsAlpha', () {
    check(
      validator: v.isAlpha,
      valid: ['abc', 'ABC', 'FoObAr'],
      invalid: ['abc1', 'AB  C', ''],
    );
  });

  test('IsAlphanumeric', () {
    check(
      validator: v.isAlphanumeric,
      valid: ['abc1', '0A1BC', 'Fo0bAr'],
      invalid: ['abc!', 'AB C', ''],
    );
  });

  test('IsNumeric', () {
    check(
        validator: v.isNumeric,
        valid: ['-1', '0', '00', '01', '19934', '-23412'],
        invalid: ['abc!', 'AB C', '']);
  });

  test('IsBase64', () {
    check(
      validator: v.isBase64,
      valid: [
        // ignore: lines_longer_than_80_chars
        'TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNlY3RldHVyIGFkaXBpc2NpbmcgZWxpdC4=',
        'Vml2YW11cyBmZXJtZW50dW0gc2VtcGVyIHBvcnRhLg==',
        'U3VzcGVuZGlzc2UgbGVjdHVzIGxlbw==',
        'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMPNS1Ufof9EW/M98FNwUAKrwflsqVxaxQjBQnHQmiI7Vac40t8x7pIb8gLGV6wL7sBTJiPovJ0V7y7oc0YerhKh0Rm4skP2z/jHwwZICgGzBvA0rH8xlhUiTvcwDCJ0kc+fh35hNt8srZQM4619FTgB66Xmp4EtVyhpQV+t02g6NzK72oZI0vnAvqhpkxLeLiMCyrI416wHm5TkukhxQmcL2a6hNOyu0ixX/x2kSFXApEnVrJ+/IxGyfyw8kf4N2IZpW5nEP847lpfj0SZZFwrd1mnfnDbYohX2zRptLy2ZUn06Qo9pkG5ntvFEPo9bfZeULtjYzIl6K8gJ2uGZHQIDAQAB'
      ],
      invalid: ['abc!', 'AB C', 'Vml2YW11cyBmZXJtZtesting123', ''],
    );
  });

  test('IsInt', () {
    check(
      validator: v.isInt,
      valid: ['-1', '0', '10', '23423', '19934', '-23412'],
      invalid: ['-01', '000', '12.13', 'AB', ''],
    );
  });

  test('IsFloat', () {
    check(
      validator: v.isFloat,
      valid: [
        '-1.324',
        '0.32',
        '-0.324',
        '-2423.234234',
        '-0.22250738585072011e-307',
        '0.22250738585072011e-307'
      ],
      invalid: ['abc!', 'AB C', ' '],
    );
  });

  test('IsHexadecimal', () {
    check(
      validator: v.isHexadecimal,
      valid: ['deadBEEF', 'ff0044'],
      invalid: ['abcdefg', ' ', '..'],
    );
  });

  test('IsHexColor', () {
    check(
      validator: v.isHexColor,
      valid: ['#ff0034', '#CCCCCC', 'fff', '#f00'],
      invalid: ['#ff', 'fff0', '#ff12FG'],
    );
  });

  test('IsLowercase', () {
    check(
      validator: v.isLowercase,
      valid: ['abc', 'abc123', 'l.o.w.e.r.', 'tr竪s 端ber'],
      invalid: ['f00Bar', 'uUu'],
    );
  });

  test('IsUppercase', () {
    check(
      validator: v.isUppercase,
      valid: ['ABC', 'ABC123', 'U.P.P.E.R.'],
      invalid: ['f00Bar', 'uUu'],
    );
  });

  test('IsDivisibleBy', () {
    check<String>(
        validator: (val) => v.isDivisibleBy(val, '2'),
        valid: ['2', '4', '100', '-10'],
        invalid: ['1', '-1', 'abc']);
  });

  test('IsNull', () {
    check(validator: v.isNull, valid: [
      null,
      '',
    ], invalid: [
      ' ',
      'foo'
    ]);
  });

  test('IsLength', () {
    check<String>(
        validator: (val) => v.isLength(val, 2),
        valid: ['ab', 'de', 'abcd', '干𩸽'],
        invalid: ['', 'a', '𠀋']);

    check<String>(
        validator: (val) => v.isLength(val, 2, 3),
        valid: ['abc', 'de', '干𩸽'],
        invalid: ['', '𠀋', '千竈通り']);
  });

  test('IsByteLength', () {
    check<String>(
        validator: (val) => v.isByteLength(val, 2),
        valid: ['abc', 'de'],
        invalid: ['', ' ']);

    check<String>(
        validator: (val) => v.isByteLength(val, 2, 3),
        valid: ['abc', 'de', '干𩸽'],
        invalid: ['', 'abcdef']);
  });

  test('IsUUID', () {
    check(validator: v.isUUID, valid: [
      'A987FBC9-4BED-3078-CF07-9141BA07C9F3',
      'A987FBC9-4BED-4078-8F07-9141BA07C9F3',
      'A987FBC9-4BED-5078-AF07-9141BA07C9F3'
    ], invalid: [
      '',
      'xxxA987FBC9-4BED-3078-CF07-9141BA07C9F3',
      'A987FBC9-4BED-3078-CF07-9141BA07C9F3xxx',
      'A987FBC94BED3078CF079141BA07C9F3',
      '934859',
      '987FBC9-4BED-3078-CF07A-9141BA07C9F3',
      'AAAAAAAA-1111-1111-AAAG-111111111111'
    ]);

    check<String>(
        validator: (val) => v.isUUID(val, version: UUIDVersion.uuidV3),
        valid: [
          'A987FBC9-4BED-3078-CF07-9141BA07C9F3'
        ],
        invalid: [
          '',
          'xxxA987FBC9-4BED-3078-CF07-9141BA07C9F3',
          'A987FBC9-4BED-3078-CF07-9141BA07C9F3xxx',
          'A987FBC94BED3078CF079141BA07C9F3',
          '934859',
          '987FBC9-4BED-3078-CF07A-9141BA07C9F3',
          'AAAAAAAA-1111-1111-AAAG-111111111111'
        ]);

    check<String>(
        validator: (val) => v.isUUID(val, version: UUIDVersion.uuidV4),
        valid: [
          '713ae7e3-cb32-45f9-adcb-7c4fa86b90c1',
          '625e63f3-58f5-40b7-83a1-a72ad31acffb',
          '57b73598-8764-4ad0-a76a-679bb6640eb1'
        ],
        invalid: [
          '',
          'xxxA987FBC9-4BED-3078-CF07-9141BA07C9F3',
          'A987FBC9-4BED-3078-CF07-9141BA07C9F3xxx',
          'A987FBC94BED3078CF079141BA07C9F3',
          '934859',
          '987FBC9-4BED-3078-CF07A-9141BA07C9F3',
          'AAAAAAAA-1111-1111-AAAG-111111111111'
        ]);

    check<String>(
        validator: (val) => v.isUUID(val, version: UUIDVersion.uuidV5),
        valid: [
          '987FBC97-4BED-5078-AF07-9141BA07C9F3',
          '987FBC97-4BED-5078-BF07-9141BA07C9F3',
          '987FBC97-4BED-5078-8F07-9141BA07C9F3'
        ],
        invalid: [
          '',
          'xxxA987FBC9-4BED-3078-CF07-9141BA07C9F3',
          'A987FBC9-4BED-3078-CF07-9141BA07C9F3xxx',
          'A987FBC94BED3078CF079141BA07C9F3',
          '934859',
          '987FBC9-4BED-3078-CF07A-9141BA07C9F3',
          'AAAAAAAA-1111-1111-AAAG-111111111111'
        ]);
  });

  test('IsDate', () {
    check(validator: v.isDate, valid: [
      '2012-02-27 13:27:00',
      '2012-02-27',
      '2011-08-04 12:00',
      '2012-02-27 13:27:00.123456z',
      '20120227',
      '2002-02-27T14:00:00-0500',
      '2002-02-27T19:00:00Z'
    ], invalid: [
      '',
      'aaaafff',
      'ABC'
    ]);
  });

  test('IsAfter', () {
    check<String>(validator: (val) => v.isAfter(val, '2005-12-12'), valid: [
      '2012-12-12',
      '2012-02-27 13:27:00',
      '2022-02-27T14:00:00-0500'
    ], invalid: [
      '2002-12-12',
      '2002-02-27 13:27:00',
      '2002-02-27T14:00:00-0500',
      ' ',
      ''
    ]);

    check(validator: v.isAfter, valid: [
      '2052-12-12',
      '2052-02-27 13:27:00',
      '2052-02-27T14:00:00-0500'
    ], invalid: [
      '2002-12-12',
      '2002-02-27 13:27:00',
      '2002-02-27T14:00:00-0500',
      ' ',
      ''
    ]);
  });

  test('IsBefore', () {
    check<String>(validator: (val) => v.isBefore(val, '2005-12-12'), valid: [
      '2002-12-12',
      '2002-02-27 13:27:00',
      '2002-02-27T14:00:00-0500'
    ], invalid: [
      '2012-12-12',
      '2012-02-27 13:27:00',
      '2022-02-27T14:00:00-0500',
      ' ',
      ''
    ]);

    check(validator: v.isBefore, valid: [
      '2002-12-12',
      '2002-02-27 13:27:00',
      '2002-02-27T14:00:00-0500'
    ], invalid: [
      '2032-12-12',
      '2032-02-27 13:27:00',
      '2032-02-27T14:00:00-0500',
      ' ',
      ''
    ]);
  });

  test('IsIn', () {
    check<String>(
        validator: (val) => v.isIn(val, ['foobar', 'foo', 'bar']),
        valid: ['foo', 'bar', 'foobar'],
        invalid: ['1', ' ', 'oba', 'oob', '']);

    check<String>(
        validator: (val) => v.isIn(val, [1, 2, 3]),
        valid: ['1', '2', '3'],
        invalid: ['4', ' ']);
  });

  test('IsCreditCard', () {
    check(validator: v.isCreditCard, valid: [
      '375556917985515',
      '36050234196908',
      '4716461583322103',
      '4716-2210-5188-5662',
      '4929 7226 5379 7141',
      '5398228707871527'
    ], invalid: [
      '5398228707871528',
      '',
      'Lol0'
    ]);
  });

  test('IsISBN', () {
    check<String>(
        validator: (val) => v.isISBN(val, version: ISBNVersion.isbn10),
        valid: [
          '3836221195',
          '3-8362-2119-5',
          '3 8362 2119 5',
          '1617290858',
          '1-61729-085-8',
          '1 61729 085-8',
          '0007269706',
          '0-00-726970-6',
          '0 00 726970 6',
          '3423214120',
          '3-423-21412-0',
          '3 423 21412 0',
          '340101319X',
          '3-401-01319-X',
          '3 401 01319 X'
        ],
        invalid: [
          '3423214121',
          '3-423-21412-1',
          '3 423 21412 1',
          '978-3836221191',
          '9783836221191',
          '123456789a',
          'foo',
          ''
        ]);

    check<String>(
        validator: (val) => v.isISBN(val, version: ISBNVersion.isbn13),
        valid: [
          '9783836221191',
          '978-3-8362-2119-1',
          '978 3 8362 2119 1',
          '9783401013190',
          '978-3401013190',
          '978 3401013190',
          '9784873113685',
          '978-4-87311-368-5',
          '978 4 87311 368 5'
        ],
        invalid: [
          '9783836221190',
          '978-3-8362-2119-0',
          '978 3 8362 2119 0',
          '3836221195',
          '3-8362-2119-5',
          '3 8362 2119 5',
          '01234567890ab',
          'foo',
          ''
        ]);

    check(validator: v.isISBN, valid: [
      '9783836221191',
      '978-3-8362-2119-1',
      '978 3 8362 2119 1',
      '9783401013190',
      '978-3401013190',
      '978 3401013190',
      '3423214120',
      '3-423-21412-0',
      '3 423 21412 0',
      '340101319X',
      '3-401-01319-X',
      '3 401 01319 X'
    ], invalid: [
      '3423214121',
      '9783836221190',
      '01234567890ab',
      'foo',
      ''
    ]);
  });

  test('IsJSON', () {
    check(
        validator: v.isJSON,
        valid: ['{"key": "v"}', '{"1": [1, 2, 3]}', '[1, 2, 3]'],
        invalid: ['foo', '{ key: "value" }', "{ 'key': 'value' }"]);
  });

  test('IsMultibyte', () {
    check(validator: v.isMultibyte, valid: [
      'ひらがな・カタカナ、．漢字',
      'あいうえお foobar',
      'test＠example.com',
      '1234abcDEｘｙｚ'
    ], invalid: [
      'abc',
      '<>@" *.'
    ]);
  });

  test('IsAscii', () {
    check(validator: v.isAscii, valid: [
      'abc',
      '<>@" *.'
    ], invalid: [
      'ひらがな・カタカナ、．漢字',
      'あいうえお foobar',
      'test＠example.com',
      '1234abcDEｘｙｚ'
    ]);
  });

  test('IsFullWidth', () {
    check(
        validator: v.isFullWidth,
        valid: ['ひらがな・カタカナ、．漢字', '３ー０　ａ＠ｃｏｍ', 'Ｆｶﾀｶﾅﾞﾬ'],
        invalid: ['abc', 'abc123', '']);
  });

  test('IsHalfWidth', () {
    check(
        validator: v.isHalfWidth,
        valid: ['l-btn_02--active', 'abc123い', 'ｶﾀｶﾅﾞﾬ￩'],
        invalid: ['００１１', 'あいうえお', '']);
  });

  test('IsVariableWidth', () {
    check(
        validator: v.isVariableWidth,
        valid: ['ひらがなカタカナ漢字ABCDE', '３ー０123', 'Ｆｶﾀｶﾅﾞﾬ', 'Good＝Parts'],
        invalid: ['abc', 'abc123', 'ひらがな・カタカナ、．漢字', '１２３４５６', '']);
  });

  test('IsSurrogatePairs', () {
    check(
        validator: v.isSurrogatePair,
        valid: ['𠮷野𠮷', '𩸽', 'ABC千𥧄1-2-3'],
        invalid: ['吉野竈', '鮪', 'ABC1-2-3']);
  });

  test('IsMongoId', () {
    check(
        validator: v.isMongoId,
        valid: ['507f1f77bcf86cd799439011'],
        invalid: ['507f1f77bcf86cd7994390', '507f1f77bcf86cd7994390z', '']);
  });
  test('IsPostalCode', () {
    check<String>(
        validator: (val) => v.isPostalCode(val, 'US'),
        valid: ['00000'],
        invalid: ['000000', 'aaaaaa', '']);
  });
}
