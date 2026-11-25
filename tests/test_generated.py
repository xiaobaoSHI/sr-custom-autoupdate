"""Verify published JSON/metadata against the actual daily source, offline.

Run both builders first. Counts are derived from the current source so ordinary
Johnshall updates do not require changing a hard-coded snapshot count.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import unittest

from tests.routing_oracle import atoms, route, rule_counts

ROOT = Path(__file__).resolve().parents[1]


class GeneratedArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "dist/sr_top500_banlist_custom_daily.conf").read_text(encoding="utf-8-sig")
        cls.rendered = (ROOT / "dist/v2rayn_daily.json").read_text(encoding="utf-8")
        cls.rules = json.loads(cls.rendered)
        cls.meta = json.loads((ROOT / "dist/v2rayn_daily.meta.json").read_text(encoding="utf-8"))
        cls.matchers = atoms(cls.rules)

    def test_source_and_output_hashes(self):
        self.assertEqual(self.meta["input_sha256"], hashlib.sha256(self.source.encode()).hexdigest())
        self.assertEqual(self.meta["output_sha256"], hashlib.sha256(self.rendered.encode()).hexdigest())
        self.assertEqual(self.meta["input_file"], "sr_top500_banlist_custom_daily.conf")

    def test_counts_conserve_every_source_and_expanded_matcher(self):
        source_counts = rule_counts(self.source)
        self.assertEqual(self.meta["input_rule_counts"], source_counts)
        expected_expanded = Counter(source_counts)
        expected_expanded.pop("RULE-SET", None)
        references = Counter()
        in_rules = False
        for line in self.source.splitlines():
            line = line.strip()
            if line.startswith("["):
                in_rules = line.lower() == "[rule]"
            elif in_rules and line.upper().startswith("RULE-SET,"):
                references[line.split(",")[1].strip()] += 1
        self.assertEqual(set(references), {remote["url"] for remote in self.meta["rulesets"]})
        remote_rule_count = 0
        for remote in self.meta["rulesets"]:
            self.assertEqual(sum(remote["rule_counts"].values()), remote["rule_count"])
            self.assertRegex(remote["sha256"], r"^[0-9a-f]{64}$")
            count = references[remote["url"]]
            remote_rule_count += remote["rule_count"] * count
            expected_expanded.update({kind: number * count for kind, number in remote["rule_counts"].items()})
        self.assertGreater(remote_rule_count, 0)
        self.assertEqual(self.meta["expanded_rule_counts"], dict(expected_expanded))
        actual_counts = Counter(field for field, _, _ in self.matchers)
        self.assertEqual(self.meta["emitted_match_counts"], dict(actual_counts))
        bypass = self.meta["bypass"]
        total_candidates = (sum(expected_expanded.values()) +
                            len(bypass["source_skip_proxy"]) + len(bypass["additional_local_ip"]))
        self.assertEqual(total_candidates - self.meta["duplicates_removed"], len(self.matchers))
        self.assertEqual(self.meta["output_rule_groups"], len(self.rules))
        self.assertEqual(self.meta["duplicates_removed"], len(self.meta["duplicates"]))

    def test_no_duplicate_predicates_remain(self):
        self.assertEqual(len(self.matchers), len(set(self.matchers)))
        for duplicate in self.meta["duplicates"]:
            self.assertIn((duplicate["field"], duplicate["value"], duplicate["outboundTag"]), self.matchers)

    def test_domain_and_ip_rules_keep_source_order_with_domains_first(self):
        # Compare source order independently for domain and IP predicates.
        # Keeping domains first prevents IPOnDemand from resolving a listed
        # proxy domain before its domain rule gets a chance to match.
        prefixes = {"DOMAIN": "full:", "DOMAIN-SUFFIX": "domain:", "DOMAIN-KEYWORD": "keyword:"}
        actions = {"PROXY": "proxy", "DIRECT": "direct", "REJECT": "block"}
        expected = {"domain": [], "ip": []}
        seen = set()

        def add(item):
            if item not in seen:
                seen.add(item)
                expected[item[0]].append(item)

        # Local bypasses are generated before source rules, but grouped by
        # predicate type in the output.
        for group in self.rules:
            if group["remarks"].startswith("Local"):
                for item in atoms([group]):
                    add(item)

        in_rules = False
        for line in self.source.splitlines():
            line = line.strip()
            if line.startswith("["):
                in_rules = line.lower() == "[rule]"
                continue
            if not in_rules or not line or line.startswith(("#", ";", "//")):
                continue
            parts = [part.strip() for part in line.split(",")]
            kind = parts[0].upper()
            if kind == "RULE-SET":
                remote_tag = actions[parts[2].upper()]
                for group in self.rules:
                    if group["remarks"] == "Apple News (expanded RULE-SET)" and group["outboundTag"] == remote_tag:
                        for item in atoms([group]):
                            add(item)
                continue
            if kind == "FINAL":
                continue
            if kind in prefixes:
                item = ("domain", prefixes[kind] + parts[1].lower(), actions[parts[2].upper()])
            else:
                self.assertIn(kind, {"IP-CIDR", "IP-CIDR6"})
                item = ("ip", str(ipaddress.ip_network(parts[1], strict=False)), actions[parts[2].upper()])
            add(item)

        actual = {"domain": [], "ip": []}
        for item in self.matchers:
            if item[0] in actual:
                actual[item[0]].append(item)
        self.assertEqual(expected, actual)

        domain_positions = [i for i, rule in enumerate(self.rules) if "domain" in rule]
        ip_positions = [i for i, rule in enumerate(self.rules) if "ip" in rule]
        self.assertTrue(domain_positions)
        self.assertTrue(ip_positions)
        self.assertLess(max(domain_positions), min(ip_positions))
        self.assertEqual(self.rules[-1]["outboundTag"], "direct")
        self.assertEqual(self.rules[-1]["port"], "0-65535")

    def test_five_custom_priority_sites_keep_priority(self):
        custom_groups = [rule for rule in self.rules if rule["remarks"] == "Custom priority rules"]
        self.assertTrue(custom_groups)
        self.assertEqual(custom_groups[0]["outboundTag"], "proxy")
        expected = ["cloudflare.com", "browserleaks.com", "ipleak.net", "dnsleaktest.com", "test-ipv6.com"]
        self.assertEqual(custom_groups[0]["domain"][:5], ["domain:" + host for host in expected])
        first_custom = self.rules.index(custom_groups[0])
        first_upstream = next(i for i, rule in enumerate(self.rules) if rule["remarks"] == "Johnshall blacklist")
        self.assertLess(first_custom, first_upstream)
        self.assertTrue(all(rule["outboundTag"] == "direct" for rule in self.rules[:first_custom]))
        for host in expected:
            with self.subTest(host=host):
                self.assertEqual(route(self.rules, host=host), "proxy")
                self.assertEqual(route(self.rules, host="www." + host), "proxy")

    def test_known_domain_behavior(self):
        expected = {
            "www.google.com": "proxy", "www.amazon.cn": "proxy",
            "cloudflare.com": "proxy", "www.cloudflare.com": "proxy", "dash.cloudflare.com": "proxy",
            "www.amazon.com": "proxy", "www.baidu.com": "direct",
            "unlisted-example.invalid": "direct", "localhost": "direct",
            "printer.local": "direct", "captive.apple.com": "direct",
        }
        for host, tag in expected.items():
            with self.subTest(host=host):
                self.assertEqual(route(self.rules, host=host), tag)

    def test_known_ip_behavior_and_local_priority(self):
        for address, tag in {
            "91.108.56.1": "proxy", "2001:b28:f23d::1": "proxy",
            "192.168.1.1": "direct", "10.1.2.3": "direct",
            "172.16.1.1": "direct", "127.0.0.1": "direct",
            "169.254.1.1": "direct", "::1": "direct", "fe80::1": "direct", "fc00::1": "direct",
        }.items():
            with self.subTest(address=address):
                self.assertEqual(route(self.rules, ip=address), tag)
        # Domain-list matches intentionally precede IP checks. A listed proxy
        # domain therefore remains proxy even if its resolved address is private.
        self.assertEqual(route(self.rules, host="www.google.com", ip="192.168.1.1"), "proxy")

    def test_only_routing_rules_and_final_direct(self):
        self.assertIsInstance(self.rules, list)
        for rule in self.rules:
            self.assertLessEqual(set(rule), {"remarks", "enabled", "outboundTag", "domain", "ip", "port"})
            self.assertIs(rule["enabled"], True)
            self.assertEqual(sum(field in rule for field in ("domain", "ip", "port")), 1)
        self.assertEqual(self.rules[-1]["outboundTag"], "direct")
        self.assertEqual(self.rules[-1]["port"], "0-65535")
        self.assertEqual(sum("port" in rule for rule in self.rules), 1)


if __name__ == "__main__":
    unittest.main()
