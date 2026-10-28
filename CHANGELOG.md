# 5.1.1
- Fix excessive backtracking in `isEmail` for domains with many short labels.
- Enforce domain label boundaries, rejecting empty labels, punctuation at label
  boundaries, and numeric starts to final labels that were previously accepted
  because dots could be consumed inside a label.
- Reject backslashes anywhere in URLs, including paths, queries and fragments,
  whether or not host lists are set.
- When either `isURL` host list is nonempty, require an explicit absolute
  `http://`, `https://` or `ftp://` URL, even with `requireProtocol: false`.
  `protocols` still restricts allowed schemes; it cannot enable custom schemes
  for host lists. Protocol-less inputs and custom schemes are rejected in this
  mode. With both lists empty, existing protocol behavior is unchanged.
- Nonempty host lists reject Unicode URL hosts and noncanonical numeric IPv4
  spellings. Host lists compare only hostnames, case-insensitively, ignoring
  ports. Both lists must contain canonical ASCII hostnames (for example,
  `example.com`, `xn--bcher-kva.com` or `127.0.0.1`), without schemes, ports or
  paths. Entries are only lowercased; Unicode and numeric aliases are not
  normalized to their canonical equivalents.
- Correct FQDN label validation and IPv6 syntax checks, including compressed
  addresses and IPv4 tails. `isIP(null)` now returns false.

# 5.1.0
- upgraded packges, fixed lints.

# 5.0.0
- upgraded to dart 3.x

# 4.0.0
- Modernised the api to confirm to post 2.12 best practices. There are a number of small breaking changes, the main theme is changing optional args to named args with a default value.

# 3.0.0
temporary release until main authors can publish nnbd version.
Migrated to nnbd

## 2.0.1

- Fix `isURL` `hostWhitelist` and `hostBlacklist` inverted logic
- Upgrade `vin_decoder` to `^0.1.2`

## 2.0.0

- Change `isUrl` and `isFQDN` `options` parameter to be optional parameters

## 1.0.0

- migrate to dart 2 and fix tests
