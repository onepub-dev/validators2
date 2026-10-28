import 'package:test/test.dart';
import 'package:validators2/validators2.dart';

void main() {
  group('URL authority validation', () {
    test('either host list requires an explicit supported absolute scheme', () {
      for (final url in [
        'allowed.com',
        'allowed.com:8080/path',
        '//allowed.com/path',
        'http:allowed.com',
        'https:/allowed.com',
        'custom://allowed.com/path',
        'file://localhost/path',
        'ws://allowed.com/path',
      ]) {
        for (final whitelist in [false, true]) {
          expect(
            isURL(url,
                protocols: ['http', 'https', 'ftp', 'custom', 'file', 'ws'],
                hostWhitelist: whitelist ? ['allowed.com', 'localhost'] : [],
                hostBlacklist: whitelist ? [] : ['unrelated.example']),
            isFalse,
            reason: '${whitelist ? 'whitelist' : 'blacklist'}: $url',
          );
        }
      }
    });

    test('host lists allow supported schemes and compare hosts without ports',
        () {
      for (final scheme in ['http', 'https', 'ftp']) {
        for (final port in ['', ':8080']) {
          final url = '$scheme://ALLOWED.COM$port/path?query=value#fragment';
          expect(isURL(url, hostWhitelist: ['allowed.com']), isTrue,
              reason: 'matching whitelist: $url');
          expect(isURL(url, hostWhitelist: ['unrelated.example']), isFalse,
              reason: 'unrelated whitelist: $url');
          expect(isURL(url, hostBlacklist: ['allowed.com']), isFalse,
              reason: 'matching blacklist: $url');
          expect(isURL(url, hostBlacklist: ['unrelated.example']), isTrue,
              reason: 'unrelated blacklist: $url');
          expect(
            isURL(url,
                hostWhitelist: ['allowed.com'],
                hostBlacklist: ['unrelated.example']),
            isTrue,
            reason: 'both lists: $url',
          );
          expect(
            isURL(url, protocols: [], hostBlacklist: ['unrelated.example']),
            isFalse,
            reason: 'protocols still restrict schemes: $url',
          );
        }
      }
      expect(
        isURL('http://allowed.com',
            protocols: ['https'], hostWhitelist: ['allowed.com']),
        isFalse,
      );
    });

    test('empty host lists preserve protocol options', () {
      for (final url in [
        'allowed.com',
        'allowed.com:8080/path',
        'custom://allowed.com/path',
        'file://localhost/path',
        'ws://allowed.com/path',
      ]) {
        expect(
          isURL(url, protocols: ['custom', 'file', 'ws']),
          isTrue,
          reason: 'omitted lists: $url',
        );
        expect(
          isURL(url,
              protocols: ['custom', 'file', 'ws'],
              hostWhitelist: [],
              hostBlacklist: []),
          isTrue,
          reason: 'explicit empty lists: $url',
        );
      }
      expect(isURL('allowed.com', requireProtocol: true), isFalse);
      expect(isURL('custom://allowed.com'), isFalse);
      expect(
        isURL('custom://allowed.com',
            protocols: ['custom'], requireProtocol: true),
        isTrue,
      );
    });

    test('rejects browser backslash authority mismatch', () {
      expect(
        isURL(r'https://evil.com\@allowed.com', hostWhitelist: ['allowed.com']),
        isFalse,
      );
      for (final url in [
        r'https://allowed.com\evil.com',
        r'https://allowed.com/path\segment',
        r'https://allowed.com/?query=\value',
        r'https://allowed.com/#\fragment',
      ]) {
        expect(isURL(url), isFalse, reason: url);
      }
    });

    test('validates whitespace throughout userinfo', () {
      for (final auth in [
        'user name',
        'user\tname',
        'user\nname',
        'user:pass word',
        'user:pass\tword',
        'user:pass\nword',
        'user:pass:word word',
        'user:pass\u00a0word',
        ':password',
      ]) {
        expect(isURL('https://$auth@example.com'), isFalse, reason: auth);
      }
      for (final auth in ['user', 'user:password', 'user:', 'user:pass:word']) {
        expect(isURL('https://$auth@example.com'), isTrue, reason: auth);
      }
    });

    test('compares both host lists without DNS case sensitivity', () {
      for (final host in ['allowed.com', 'ALLOWED.COM', 'AlLoWeD.CoM']) {
        for (final listed in ['allowed.com', 'ALLOWED.COM', 'AlLoWeD.CoM']) {
          expect(isURL('https://$host', hostWhitelist: [listed]), isTrue);
          expect(isURL('https://$host', hostBlacklist: [listed]), isFalse);
        }
      }
      expect(
          isURL('https://evil.com', hostWhitelist: ['ALLOWED.COM']), isFalse);
      expect(isURL('https://evil.com', hostBlacklist: ['ALLOWED.COM']), isTrue);
      expect(
        isURL('https://allowed.com',
            hostWhitelist: ['ALLOWED.COM'], hostBlacklist: ['Allowed.Com']),
        isFalse,
      );
    });

    test('host blacklist rejects browser loopback aliases', () {
      for (final url in [
        'http://0177.0.0.1/',
        'http://2130706433/',
        'http://0x7f.0.0.1/',
        'http://１２７.０.０.１/',
      ]) {
        expect(
          isURL(url, hostBlacklist: ['127.0.0.1'], requireTld: false),
          isFalse,
          reason: url,
        );
      }
    });

    test('either nonempty host list requires unambiguous ASCII hosts', () {
      for (final host in [
        '0177.0.0.1',
        '127.00.0.1',
        '127.0.0.01',
        '127.1',
        '2130706433',
        '0x7f000001',
        '0X7F.0.0.1',
        '0x7f.0x0.0x0.0x1',
        '017700000001',
        '127.0.0x',
        '256.0.0.1',
        '１２７.０.０.１',
        'bücher.com',
        '例子.com',
        'K.example.com',
        'ｅxample.com',
        'example。com',
      ]) {
        expect(
          isURL('http://$host/', hostWhitelist: [host], requireTld: false),
          isFalse,
          reason: 'whitelist: $host',
        );
        expect(
          isURL('http://$host/',
              hostBlacklist: ['unrelated.example'], requireTld: false),
          isFalse,
          reason: 'blacklist: $host',
        );
      }
    });

    test('host lists preserve ASCII DNS and canonical dotted IPv4', () {
      for (final host in [
        'example.com',
        'EXAMPLE.COM',
        '123.example.com',
        '0x7f.example.com',
        'xn--bcher-kva.com',
        'localhost',
        'intranet',
        '0.0.0.0',
        '127.0.0.1',
        '192.168.0.1',
        '255.255.255.255',
      ]) {
        expect(
          isURL('http://$host:8080/path',
              hostWhitelist: [host.toUpperCase()], requireTld: false),
          isTrue,
          reason: 'whitelist: $host',
        );
        expect(
          isURL('http://$host/',
              hostBlacklist: ['unrelated.example'], requireTld: false),
          isTrue,
          reason: 'unrelated blacklist: $host',
        );
        expect(
          isURL('http://$host/',
              hostBlacklist: [host.toUpperCase()], requireTld: false),
          isFalse,
          reason: 'matching blacklist: $host',
        );
      }
    });

    test('empty host lists retain existing host spelling behavior', () {
      for (final host in ['bücher.com', '0177.0.0.1', '2130706433']) {
        expect(isURL('http://$host/', requireTld: false), isTrue, reason: host);
        expect(
          isURL('http://$host/',
              hostWhitelist: [], hostBlacklist: [], requireTld: false),
          isTrue,
          reason: host,
        );
      }
    });

    test('preserves normal URL options', () {
      expect(
          isURL('https://EXAMPLE.COM:443/path?query=value#fragment'), isTrue);
      expect(isURL('http://LOCALHOST:8080'), isTrue);
      expect(isURL('http://127.0.0.1:8080'), isTrue);
      expect(
          isURL('https://service_name.example', allowUnderscore: true), isTrue);
      expect(isURL('https://service_name.example'), isFalse);
      expect(isURL('intranet', requireTld: false), isTrue);
      expect(isURL('example.com', requireProtocol: true), isFalse);
    });
  });

  group('FQDN label validation', () {
    test('accepts ordinary, uppercase and international labels', () {
      for (final domain in [
        'example.com',
        'EXAMPLE.COM',
        'sub.Example.CoM',
        'bücher.com',
        '例子.com',
        'xn--bcher-kva.com',
        'foo--bar.com',
        '${'a' * 63}.com',
        'example.${'a' * 63}',
      ]) {
        expect(isFQDN(domain), isTrue, reason: domain);
      }
    });

    test('rejects malformed and oversized labels', () {
      for (final domain in [
        '',
        '.com',
        'example..com',
        'example.com.',
        '-example.com',
        'example-.com',
        'foo---bar.com',
        r'exam\ple.com',
        'exam[ple.com',
        'exam@ple.com',
        'exam ple.com',
        'exam\u00a0ple.com',
        'exam\u2003ple.com',
        'example.com\n',
        'example.1a',
        '${'a' * 64}.com',
        'example.${'a' * 64}',
      ]) {
        expect(isFQDN(domain), isFalse, reason: domain);
      }
    });

    test('handles underscores and optional TLD explicitly', () {
      expect(isFQDN('foo_bar.example'), isFalse);
      expect(isFQDN('foo_bar.example', allowUnderscores: true), isTrue);
      expect(isFQDN('foo__bar.example', allowUnderscores: true), isFalse);
      expect(isFQDN('intranet', requireTld: false), isTrue);
      expect(isFQDN('INTRANET', requireTld: false), isTrue);
      expect(isFQDN('intranet'), isFalse);
      for (final domain in ['', 'a..b', '.a', 'a.', 'a' * 64]) {
        expect(isFQDN(domain, requireTld: false), isFalse, reason: domain);
      }
    });
  });

  group('IP syntax', () {
    test('rejects null for every version', () {
      for (final version in IPVersion.values) {
        expect(isIP(null, version: version), isFalse);
      }
    });

    test('accepts complete and compressed IPv6 with optional IPv4 tail', () {
      for (final address in [
        '::',
        '::1',
        '1::',
        '2001:db8::1',
        '2001:DB8:0:1:2:3:4:5',
        '1:2:3:4:5:6:7::',
        '::1:2:3:4:5:6:7',
        '1:2:3::4:5:6:7',
        '::192.0.2.1',
        '::ffff:192.0.2.1',
        '1:2:3:4:5:6:192.0.2.1',
        '1:2:3:4:5::192.0.2.1',
        '::ffff:255.255.255.255',
      ]) {
        expect(isIP(address, version: IPVersion.ipV6), isTrue, reason: address);
        expect(isIP(address), isTrue, reason: address);
        expect(isIP(address, version: IPVersion.ipV4), isFalse,
            reason: address);
      }
    });

    test('rejects malformed IPv6 without accepting a valid prefix', () {
      for (final address in [
        '',
        ':',
        ':::',
        '::garbage',
        '::1garbage',
        '::1\n',
        ' ::1',
        '1:2',
        '1:2:3:4:5:6:7',
        '1:2:3:4:5:6:7:8:9',
        '1:2:3:4:5:6:7:8::',
        '::1:2:3:4:5:6:7:8',
        '1::2::3',
        '1:::2',
        ':1:2:3:4:5:6:7',
        '1:2:3:4:5:6:7:',
        '12345::',
        'gggg::',
        '::ffff:256.0.0.1',
        '::ffff:192.168.001.1',
        '::ffff:192.0.2',
        '::ffff:192.0.2.1.2',
        '::ffff:192.0.2.1\n',
        '192.0.2.1::',
        '::192.0.2.1:1',
        '1:2:3:4:5:192.0.2.1',
        '1:2:3:4:5:6:7:192.0.2.1',
        '1:2:3:4:5:6::192.0.2.1',
        '[::1]',
        'fe80::1%eth0',
        '::1/128',
      ]) {
        expect(isIP(address, version: IPVersion.ipV6), isFalse,
            reason: address);
        expect(isIP(address), isFalse, reason: address);
      }
    });

    test('preserves standalone IPv4 behavior', () {
      for (final address in ['0.0.0.0', '255.255.255.255', '001.002.003.004']) {
        expect(isIP(address, version: IPVersion.ipV4), isTrue, reason: address);
        expect(isIP(address), isTrue, reason: address);
        expect(isIP(address, version: IPVersion.ipV6), isFalse,
            reason: address);
      }
      for (final address in ['256.0.0.1', '1.2.3', '1.2.3.4.5', '-1.2.3.4']) {
        expect(isIP(address, version: IPVersion.ipV4), isFalse,
            reason: address);
      }
    });
  });
}
