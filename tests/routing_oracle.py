"""Independent, DNS-free matcher for the generated Xray routing subset.

This is a semantic regression oracle, not an Xray/network integration test.
It deliberately does not call the converter's parsing or conversion functions.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter


def domain_matches(pattern: str, host: str) -> bool:
    host = host.lower()
    if pattern.startswith("full:"):
        return host == pattern[5:]
    if pattern.startswith("domain:"):
        suffix = pattern[7:]
        return host == suffix or host.endswith("." + suffix)
    if pattern.startswith("keyword:"):
        return pattern[8:] in host
    if pattern.startswith("regexp:"):
        return re.search(pattern[7:], host) is not None
    return pattern in host


def route(rules: list[dict], host: str | None = None,
          ip: str | None = None, port: int = 443) -> str | None:
    address = ipaddress.ip_address(ip) if ip is not None else None
    for rule in rules:
        if rule.get("enabled", True) is False:
            continue
        if "domain" in rule and not (
            host and any(domain_matches(p, host) for p in rule["domain"])
        ):
            continue
        if "ip" in rule and not (
            address and any(address in ipaddress.ip_network(p) for p in rule["ip"])
        ):
            continue
        if "port" in rule:
            ranges = [part.split("-") for part in rule["port"].split(",")]
            if not any(int(p[0]) <= port <= int(p[-1]) for p in ranges):
                continue
        return rule["outboundTag"]
    return None


def atoms(rules: list[dict]) -> list[tuple[str, str, str]]:
    result = []
    for rule in rules:
        for field in ("domain", "ip", "port"):
            if field not in rule:
                continue
            values = [rule[field]] if field == "port" else rule[field]
            result.extend((field, value, rule["outboundTag"]) for value in values)
    return result


def rule_counts(text: str) -> dict[str, int]:
    section = None
    counts = Counter()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line.lower()
        elif section == "[rule]" and line and not line.startswith(("#", ";", "//")):
            counts[line.split(",", 1)[0].upper()] += 1
    return dict(counts)
