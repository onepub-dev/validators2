# 5.1.1
- Fix excessive backtracking in `isEmail` for domains with many short labels.
- Enforce domain label boundaries, rejecting empty labels, punctuation at label
  boundaries, and numeric starts to final labels that were previously accepted
  because dots could be consumed inside a label.
- Reject URL spellings that browsers interpret with a different host, including
  backslashes and noncanonical numeric or Unicode hosts when a host list is set.
  Host lists now compare ASCII DNS names without case sensitivity.
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
