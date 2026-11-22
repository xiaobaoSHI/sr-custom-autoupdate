"""Offline converter tests. No requests are made to upstream servers."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_v2rayn import APPLE_NEWS_URL, ConversionError, convert_config
from tests.routing_oracle import atoms, route, rule_counts

APPLE_NEWS = (ROOT / "tests/fixtures/AppleNews.list").read_text(encoding="utf-8")
GENERAL = """[General]
skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com
dns-server = system,223.5.5.5,119.29.29.29
fallback-dns-server = 1.1.1.1,8.8.8.8
ipv6 = false
prefer-ipv6 = false
"""


def config(body: str, general: str = GENERAL) -> str:
    return general + "\n[Rule]\n" + body + "\nFINAL,DIRECT\n"


def convert(body: str):
    return convert_config(config(body), fetcher=lambda _: APPLE_NEWS)


class ConverterTests(unittest.TestCase):
    def test_json_array_schema_is_rulesitem_subset(self):
        rules, _ = convert("DOMAIN-SUFFIX,example.com,PROXY\nIP-CIDR,8.8.8.0/24,PROXY")
        self.assertEqual(json.loads(json.dumps(rules)), rules)
        for rule in rules:
            self.assertLessEqual(set(rule), {"remarks", "enabled", "outboundTag", "domain", "ip", "port"})
            self.assertIn(rule["outboundTag"], {"direct", "proxy", "block"})
            self.assertIs(rule["enabled"], True)
            self.assertEqual(sum(k in rule for k in ("domain", "ip", "port")), 1)
            if "domain" in rule or "ip" in rule:
                values = rule.get("domain", rule.get("ip"))
                self.assertIsInstance(values, list)
                self.assertTrue(values)
                self.assertTrue(all(isinstance(value, str) for value in values))

    def test_exact_and_suffix_boundaries(self):
        rules, _ = convert("DOMAIN,only.example,PROXY\nDOMAIN-SUFFIX,example.com,PROXY")
        for host in ("only.example", "example.com", "www.example.com", "WWW.EXAMPLE.COM"):
            with self.subTest(host=host):
                self.assertEqual(route(rules, host=host), "proxy")
        for host in ("sub.only.example", "notexample.com", "example.com.evil.test"):
            with self.subTest(host=host):
                self.assertEqual(route(rules, host=host), "direct")

    def test_keyword_is_substring_not_suffix(self):
        rules, _ = convert("DOMAIN-KEYWORD,amazon,PROXY\nDOMAIN-KEYWORD,goog,PROXY")
        for host in ("www.amazon.cn", "amazonaws.test", "xamazonx.test", "www.google.com", "goog.test"):
            with self.subTest(host=host):
                self.assertEqual(route(rules, host=host), "proxy")
        self.assertEqual(route(rules, host="www.baidu.com"), "direct")

    def test_ipv4_and_ipv6_cidr_boundaries(self):
        rules, _ = convert("IP-CIDR,91.108.56.0/22,PROXY\nIP-CIDR,2001:b28:f23d::/48,PROXY")
        for address in ("91.108.56.0", "91.108.59.255", "2001:b28:f23d::", "2001:b28:f23d:ffff::1"):
            with self.subTest(address=address):
                self.assertEqual(route(rules, ip=address), "proxy")
        for address in ("91.108.55.255", "91.108.60.0", "2001:b28:f23e::1"):
            with self.subTest(address=address):
                self.assertEqual(route(rules, ip=address), "direct")

    def test_ip_cidr6_alias_and_reject_action(self):
        rules, _ = convert("IP-CIDR6,2001:db8:1234::/48,REJECT")
        self.assertEqual(route(rules, ip="2001:db8:1234::1"), "block")
        self.assertEqual(route(rules, ip="2001:db8:1235::1"), "direct")
        with self.assertRaises(ConversionError):
            convert("IP-CIDR6,8.8.8.0/24,PROXY")

    def test_local_bypass_precedes_conflicting_rules(self):
        body = "\n".join([
            "DOMAIN,localhost,PROXY", "DOMAIN-SUFFIX,local,PROXY",
            "DOMAIN-SUFFIX,apple.com,PROXY", "IP-CIDR,192.168.1.0/24,PROXY",
            "IP-CIDR,127.0.0.0/8,PROXY", "IP-CIDR,fc00::/7,PROXY",
        ])
        rules, _ = convert(body)
        for host in ("localhost", "printer.local", "a.b.local", "captive.apple.com"):
            with self.subTest(host=host):
                self.assertEqual(route(rules, host=host), "direct")
        for address in ("192.168.1.2", "127.0.0.1", "fc00::1", "fe80::1", "::1"):
            with self.subTest(address=address):
                self.assertEqual(route(rules, ip=address), "direct")
        self.assertEqual(route(rules, host="local"), "proxy")
        self.assertEqual(route(rules, host="sub.captive.apple.com"), "proxy")

    def test_custom_exception_order_survives_grouping(self):
        body = "\n".join([
            "DOMAIN,private.example.com,DIRECT",
            "DOMAIN-SUFFIX,example.com,PROXY",
            "DOMAIN,late.example.com,DIRECT",
            "DOMAIN-KEYWORD,amazon,PROXY",
            "DOMAIN,www.amazon.cn,DIRECT",
        ])
        rules, _ = convert(body)
        self.assertEqual(route(rules, host="private.example.com"), "direct")
        self.assertEqual(route(rules, host="late.example.com"), "proxy")
        self.assertEqual(route(rules, host="www.amazon.cn"), "proxy")

    def test_domain_and_ip_order_are_not_rearranged(self):
        body = "\n".join([
            "IP-CIDR,8.8.8.0/24,DIRECT",
            "DOMAIN-SUFFIX,example.com,PROXY",
            "IP-CIDR,9.9.9.0/24,DIRECT",
        ])
        rules, _ = convert(body)
        self.assertEqual(route(rules, host="example.com", ip="8.8.8.8"), "direct")
        self.assertEqual(route(rules, host="example.com", ip="9.9.9.9"), "proxy")

    def test_identical_duplicates_removed_without_moving_first(self):
        rules, meta = convert("\n".join([
            "DOMAIN-SUFFIX,example.com,PROXY",
            "DOMAIN-SUFFIX,example.com,DIRECT",
            "DOMAIN-SUFFIX,example.com,PROXY",
            "IP-CIDR,8.8.8.0/24,PROXY",
            "IP-CIDR,8.8.8.0/24,PROXY",
        ]))
        values = atoms(rules)
        self.assertEqual(len(values), len(set(values)))
        self.assertEqual(meta["duplicates_removed"], 2)
        self.assertIn(("domain", "domain:example.com", "direct"), values)
        self.assertEqual(route(rules, host="example.com"), "proxy")

    def test_comments_blank_lines_and_case(self):
        rules, meta = convert("\n# comment\n; comment\n// comment\nDOMAIN-SUFFIX,example.com,Proxy\n")
        self.assertEqual(meta["input_rule_counts"], {"DOMAIN-SUFFIX": 1, "FINAL": 1})
        self.assertEqual(route(rules, host="example.com"), "proxy")

    def test_final_direct_covers_all_ports(self):
        rules, _ = convert("DOMAIN-SUFFIX,example.com,PROXY")
        self.assertEqual(rules[-1]["outboundTag"], "direct")
        self.assertEqual(rules[-1]["port"], "0-65535")
        self.assertEqual(sum("port" in rule for rule in rules), 1)
        for port in (0, 1, 53, 443, 65535):
            with self.subTest(port=port):
                self.assertEqual(route(rules, host="unlisted.invalid", port=port), "direct")

    def test_dns_ipv6_options_do_not_enter_json(self):
        rules, _ = convert("DOMAIN-SUFFIX,example.com,PROXY")
        keys = {key for rule in rules for key in rule}
        self.assertFalse(keys & {"dns", "domainStrategy", "domainMatcher", "ipv6", "prefer-ipv6", "sniffing", "routing"})

    def test_apple_news_expands_current_two_exact_domains(self):
        fetch = Mock(return_value=APPLE_NEWS)
        text = config(f"RULE-SET,{APPLE_NEWS_URL},PROXY")
        rules, meta = convert_config(text, fetcher=fetch)
        fetch.assert_called_once_with(APPLE_NEWS_URL)
        for host in ("gspe1-ssl.ls.apple.com", "news-client-search.apple.com"):
            self.assertEqual(route(rules, host=host), "proxy")
            self.assertEqual(route(rules, host="sub." + host), "direct")
        self.assertEqual(meta["rulesets"][0]["rule_count"], 2)
        self.assertEqual(meta["rulesets"][0]["rule_counts"], {"DOMAIN": 2})
        self.assertEqual(meta["rulesets"][0]["sha256"], hashlib.sha256(APPLE_NEWS.encode()).hexdigest())
        self.assertTrue(all("RULE-SET" not in value and "https://" not in value
                            for _, value, _ in atoms(rules)))

    def test_ruleset_inherits_outer_direct_action(self):
        rules, _ = convert_config(config(f"RULE-SET,{APPLE_NEWS_URL},DIRECT\nDOMAIN-SUFFIX,apple.com,PROXY"), fetcher=lambda _: APPLE_NEWS)
        self.assertEqual(route(rules, host="news-client-search.apple.com"), "direct")
        self.assertEqual(route(rules, host="elsewhere.apple.com"), "proxy")

    def test_ruleset_expands_in_place(self):
        body = f"DOMAIN,gspe1-ssl.ls.apple.com,DIRECT\nRULE-SET,{APPLE_NEWS_URL},PROXY\nDOMAIN,news-client-search.apple.com,DIRECT"
        rules, _ = convert(body)
        self.assertEqual(route(rules, host="gspe1-ssl.ls.apple.com"), "direct")
        self.assertEqual(route(rules, host="news-client-search.apple.com"), "proxy")

    def test_ruleset_failure_does_not_silently_drop_rules(self):
        text = config(f"RULE-SET,{APPLE_NEWS_URL},PROXY")
        for response in ("", "# comments only\n", "<html>error</html>", "GEOIP,CN", "FINAL,DIRECT", f"RULE-SET,{APPLE_NEWS_URL}"):
            with self.subTest(response=response), self.assertRaises(ConversionError):
                convert_config(text, fetcher=lambda _: response)
        with self.assertRaises((ConversionError, OSError)):
            convert_config(text, fetcher=Mock(side_effect=OSError("network unavailable")))

    def test_unknown_remote_is_not_fetched(self):
        fetch = Mock(side_effect=AssertionError("must not fetch"))
        for url in ("http://example.com/rules", "https://example.com/rules"):
            with self.subTest(url=url), self.assertRaises(ConversionError):
                convert_config(config(f"RULE-SET,{url},PROXY"), fetcher=fetch)
        fetch.assert_not_called()

    def test_unknown_or_unrepresentable_rules_fail_closed(self):
        bodies = [
            "GEOIP,CN,DIRECT", "DOMAIN-SUFFIX,example.com,UNKNOWN",
            "DOMAIN-SUFFIX,example.com", "IP-CIDR,invalid,PROXY",
            "IP-CIDR,8.8.8.0/24,PROXY,no-resolve",
            "DOMAIN-SUFFIX,example.com,PROXY,extra",
            "DOMAIN-SUFFIX,,PROXY",
            "DOMAIN-SUFFIX,https://example.com,PROXY",
            "DOMAIN-SUFFIX,regexp:.*,PROXY",
        ]
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(ConversionError):
                convert(body)

    def test_bom_and_crlf_parse_like_lf(self):
        text = config("DOMAIN-SUFFIX,example.com,PROXY")
        rules, _ = convert_config(text)
        other_rules, _ = convert_config("\ufeff" + text.replace("\n", "\r\n"))
        self.assertEqual(other_rules, rules)

    def test_bad_sections_and_bypass_fail_closed(self):
        text = config("DOMAIN-SUFFIX,example.com,PROXY")
        malformed = [
            text + "\n[Rule]\nFINAL,DIRECT\n",
            text + "\n[Rewrite]\nanything\n",
            text.replace("skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com", "skip-proxy = "),
            text.replace("[Rule]", "skip-proxy = localhost\n[Rule]"),
        ]
        for value in malformed:
            with self.subTest(value=value), self.assertRaises(ConversionError):
                convert_config(value)

    def test_missing_duplicate_or_nonfinal_direct_tail_rejected(self):
        bodies = [
            "DOMAIN-SUFFIX,example.com,PROXY",
            "FINAL,PROXY", "FINAL,DIRECT\nFINAL,DIRECT",
            "FINAL,DIRECT\nDOMAIN-SUFFIX,example.com,PROXY",
        ]
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(ConversionError):
                convert_config(GENERAL + "\n[Rule]\n" + body)
        with self.assertRaises(ConversionError):
            convert_config("[General]\nskip-proxy = localhost\n")

    def test_metadata_counts_and_hash_are_auditable(self):
        text = config(f"DOMAIN-SUFFIX,example.com,PROXY\nDOMAIN-SUFFIX,example.com,PROXY\nRULE-SET,{APPLE_NEWS_URL},PROXY")
        rules, meta = convert_config(text, fetcher=lambda _: APPLE_NEWS)
        self.assertEqual(meta["input_sha256"], hashlib.sha256(text.encode()).hexdigest())
        self.assertEqual(meta["input_rule_counts"], rule_counts(text))
        self.assertEqual(meta["expanded_rule_counts"], {"DOMAIN-SUFFIX": 2, "DOMAIN": 2, "FINAL": 1})
        self.assertEqual(meta["output_rule_groups"], len(rules))
        self.assertEqual(sum(meta["emitted_match_counts"].values()), len(atoms(rules)))
        self.assertEqual(meta["duplicates_removed"], len(meta["duplicates"]))

    def test_same_input_and_remote_snapshot_is_deterministic(self):
        text = config(f"RULE-SET,{APPLE_NEWS_URL},PROXY")
        self.assertEqual(convert_config(text, fetcher=lambda _: APPLE_NEWS), convert_config(text, fetcher=lambda _: APPLE_NEWS))


if __name__ == "__main__":
    unittest.main()
