# Offline fixtures

`AppleNews.list` is the complete two-domain upstream list inspected on
2026-11-22. Its source is
[blackmatrix7 AppleNews.list](https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/AppleNews/AppleNews.list).
The upstream header records `2026-01-26 02:06:40` as its update time.

This fixture is only for offline unit tests. Production builds fetch the current
remote list and record its SHA-256 and expanded counts in `dist/v2rayn_daily.meta.json`.
Generated-artifact tests derive counts from the current daily `.conf` and metadata;
they do not pin the changing Johnshall list to a fixed number of domains.
