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

    def test_every_top_level_matcher_survives_in_original_order(self):
        # Independent parser of this source grammar, not the conversion API.
        prefixes = {"DOMAIN": "full:", "DOMAIN-SUFFIX": "domain:", "DOMAIN-KEYWORD": "keyword:"}
        actions = {"PROXY": "proxy", "DIRECT": "direct", "REJECT": "block"}
        # Source DIRECT rules may repeat an earlier bypass matcher; those
        # legitimately keep the bypass position after global deduplication.
        seen = set()
        skip_line = next(line for line in self.source.splitlines()
                         if line.strip().lower().startswith("skip-proxy"))
        skip_values = [value.strip() for value in skip_line.split("=", 1)[1].split(",")]
        self.assertEqual(skip_values, self.meta["bypass"]["source_skip_proxy"])
        for value in skip_values:
            try:
                item = ("ip", str(ipaddress.ip_network(value, strict=False)), "direct")
            except ValueError:
                pattern = ("regexp:^.+\\." + re.escape(value[2:].lower()) + "$"
                           if value.startswith("*.") else "full:" + value.lower())
                item = ("domain", pattern, "direct")
            seen.add(item)
        seen.update(("ip", value, "direct") for value in self.meta["bypass"]["additional_local_ip"])
        previous_index = -1
        in_rules = False
        positions = {item: index for index, item in enumerate(self.matchers)}
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
                # Remote contents can change independently of the fixture.
                # Expanded remote matchers are already counted above; a later
                # source rule duplicating one keeps its remote position.
                remote_tag = actions[parts[2].upper()]
                for group in self.rules:
                    if group["remarks"] == "Apple News (expanded RULE-SET)" and group["outboundTag"] == remote_tag:
                        seen.update(atoms([group]))
                continue
            if kind == "FINAL":
                item = ("port", "0-65535", "direct")
            elif kind in prefixes:
                item = ("domain", prefixes[kind] + parts[1].lower(), actions[parts[2].upper()])
            else:
                self.assertIn(kind, {"IP-CIDR", "IP-CIDR6"})
                item = ("ip", str(ipaddress.ip_network(parts[1], strict=False)), actions[parts[2].upper()])
            if item in seen:
                continue
            seen.add(item)
            self.assertIn(item, positions)
            self.assertGreater(positions[item], previous_index)
            previous_index = positions[item]

    def test_four_custom_detection_sites_keep_priority(self):
        custom_groups = [rule for rule in self.rules if rule["remarks"] == "Custom priority rules"]
        self.assertTrue(custom_groups)
        self.assertEqual(custom_groups[0]["outboundTag"], "proxy")
        expected = ["browserleaks.com", "ipleak.net", "dnsleaktest.com", "test-ipv6.com"]
        self.assertEqual(custom_groups[0]["domain"][:4], ["domain:" + host for host in expected])
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
        # When Xray knows both a local IP and a blacklisted host, bypass wins.
        self.assertEqual(route(self.rules, host="www.google.com", ip="192.168.1.1"), "direct")

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
