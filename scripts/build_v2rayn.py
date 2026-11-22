#!/usr/bin/env python3
"""Convert the existing daily build to v2rayN 7.25.6 RulesItem JSON.

Run build.py first. Reading its output keeps both clients on the same upstream
snapshot and custom/rules_prepend.conf without changing the Shadowrocket build.
This is a routing-only export: DNS, IPv6 switches and domainStrategy are not
copied. Unsupported input aborts the build instead of silently dropping rules.
"""
from __future__ import annotations

import argparse
from collections import Counter
from collections.abc import Callable
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
APPLE_NEWS_URL = (
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
    "rule/Shadowrocket/AppleNews/AppleNews.list"
)
# Explicit local routing bypass, not a change to IPv6 availability or DNS.
# Do not copy the much broader upstream bypass-tun list into this daily export.
ADDITIONAL_LOCAL_IP = (
    "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7"
)
POLICIES = {"PROXY": "proxy", "DIRECT": "direct", "REJECT": "block"}
DOMAIN_PREFIXES = {"DOMAIN": "full:", "DOMAIN-SUFFIX": "domain:",
                   "DOMAIN-KEYWORD": "keyword:"}


class ConversionError(ValueError):
    """Input cannot be represented without changing its routing semantics."""


def fetch_text(url: str) -> str:
    request = Request(url, headers={"User-Agent": "sr-custom-autoupdate/v2rayn"})
    with urlopen(request, timeout=90) as response:
        return response.read().decode("utf-8-sig")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def json_text(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _domain(value: str) -> str:
    # Hostname labels in the upstream also contain underscores. Reject syntax
    # that could accidentally become an Xray prefix, regexp, wildcard or URL.
    value = value.lower()
    if (not value or not re.fullmatch(r"[a-z0-9_.-]+", value)
            or value.startswith(".") or value.endswith(".") or ".." in value):
        raise ConversionError(f"Unsupported domain/keyword: {value!r}")
    return value


def _cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ConversionError(f"Invalid IP/CIDR: {value!r}") from exc


def _sections(text: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for raw in text.lstrip("\ufeff").splitlines():
        line = raw.strip()
        if line.startswith("["):
            if not re.fullmatch(r"\[[A-Za-z]+\]", line):
                raise ConversionError(f"Invalid section: {line}")
            current = line[1:-1].lower()
            if current in sections:
                raise ConversionError(f"Repeated section: {line}")
            if current not in {"general", "rule"}:
                raise ConversionError(f"Unsupported section: {line}")
            sections[current] = []
        elif current:
            sections[current].append(line)
        elif line and not _comment(line):
            raise ConversionError(f"Unexpected content before sections: {line}")
    if "general" not in sections or "rule" not in sections:
        raise ConversionError("Expected [General] and [Rule] sections")
    return sections


def _comment(line: str) -> bool:
    return line.startswith(("#", ";", "//"))


def convert_config(
    text: str, fetcher: Callable[[str], str] = fetch_text
) -> tuple[list[dict], dict]:
    """Return RulesItem array and deterministic provenance/count metadata.

    Only adjacent predicates with the same field, action and source group are
    combined. A domain and an IP condition MUST NOT share one Xray rule: that
    would mean AND instead of OR. Exact duplicates retain their first position.
    fetcher can be replaced with a fixture loader for fully offline tests.
    """
    sections = _sections(text)
    rules: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    duplicates: list[dict] = []
    emitted: Counter[str] = Counter()
    input_counts: Counter[str] = Counter()
    expanded_counts: Counter[str] = Counter()
    ruleset_cache: dict[str, list[tuple[str, str]]] = {}
    rulesets: list[dict] = []

    def emit(field: str, value: str, tag: str, remarks: str) -> None:
        key = (field, value, tag)
        if key in seen:
            duplicates.append({"field": field, "value": value, "outboundTag": tag})
            return
        seen.add(key)
        emitted[field] += 1
        if (field != "port" and rules and rules[-1]["remarks"] == remarks
                and rules[-1]["outboundTag"] == tag and field in rules[-1]):
            rules[-1][field].append(value)
        else:
            rules.append({"remarks": remarks, "enabled": True, "outboundTag": tag,
                          field: value if field == "port" else [value]})

    skip_proxy: list[str] | None = None
    for line in sections["general"]:
        if not line or _comment(line):
            continue
        key, sep, value = line.partition("=")
        if not sep:
            raise ConversionError(f"Malformed General setting: {line}")
        if key.strip().lower() == "skip-proxy":
            if skip_proxy is not None:
                raise ConversionError("Repeated skip-proxy setting")
            skip_proxy = [item.strip() for item in value.split(",")]
    if not skip_proxy or not all(skip_proxy):
        raise ConversionError("Missing or empty skip-proxy setting")
    for value in skip_proxy:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            if value.startswith("*."):
                suffix = _domain(value[2:])
                emit("domain", "regexp:^.+\\." + re.escape(suffix) + "$",
                     "direct", "Local bypass (daily skip-proxy)")
            else:
                emit("domain", "full:" + _domain(value), "direct",
                     "Local bypass (daily skip-proxy)")
        else:
            emit("ip", str(network), "direct", "Local bypass (daily skip-proxy)")
    for value in ADDITIONAL_LOCAL_IP:
        emit("ip", value, "direct", "Local loopback/link-local/ULA bypass")

    def convert_leaf(kind: str, value: str, policy: str, remarks: str) -> None:
        if policy not in POLICIES:
            raise ConversionError(f"Unsupported policy: {policy}")
        expanded_counts[kind] += 1
        if kind in DOMAIN_PREFIXES:
            emit("domain", DOMAIN_PREFIXES[kind] + _domain(value), POLICIES[policy], remarks)
        elif kind in {"IP-CIDR", "IP-CIDR6"}:
            network = _cidr(value)
            if kind == "IP-CIDR6" and ipaddress.ip_network(network).version != 6:
                raise ConversionError(f"IP-CIDR6 is not IPv6: {value}")
            emit("ip", network, POLICIES[policy], remarks)
        else:
            raise ConversionError(f"Unsupported rule type: {kind}")

    def expand_ruleset(url: str, policy: str) -> None:
        if url != APPLE_NEWS_URL:
            raise ConversionError(f"Unreviewed RULE-SET URL: {url}")
        if url not in ruleset_cache:
            try:
                remote = fetcher(url)
            except Exception as exc:
                raise ConversionError(f"Unable to load RULE-SET {url}: {exc}") from exc
            entries: list[tuple[str, str]] = []
            counts: Counter[str] = Counter()
            for line in remote.lstrip("\ufeff").splitlines():
                line = line.strip()
                if not line or _comment(line):
                    continue
                parts = [part.strip() for part in line.split(",")]
                # A RULE-SET contains matchers; the referring rule supplies its
                # action. Reject nested sets, embedded actions and DNS flags.
                if len(parts) != 2 or not all(parts):
                    raise ConversionError(f"Unsupported RULE-SET entry: {line}")
                kind, value = parts[0].upper(), parts[1]
                if kind not in {*DOMAIN_PREFIXES, "IP-CIDR", "IP-CIDR6"}:
                    raise ConversionError(f"Unsupported RULE-SET type: {kind}")
                entries.append((kind, value))
                counts[kind] += 1
            if not entries:
                raise ConversionError(f"Empty RULE-SET: {url}")
            ruleset_cache[url] = entries
            rulesets.append({"url": url, "sha256": sha256(remote),
                             "rule_count": len(entries), "rule_counts": dict(sorted(counts.items()))})
        for kind, value in ruleset_cache[url]:
            convert_leaf(kind, value, policy, "Apple News (expanded RULE-SET)")

    final_seen = False
    remarks = "Daily routing rules"
    for line in sections["rule"]:
        if not line:
            continue
        if _comment(line):
            if line == "# ---- custom rules begin ----":
                remarks = "Custom priority rules"
            elif line == "# ---- upstream Johnshall rules begin ----":
                remarks = "Johnshall blacklist"
            continue
        if final_seen:
            raise ConversionError("FINAL,DIRECT must be the last rule (and appear only once)")
        parts = [part.strip() for part in line.split(",")]
        kind = parts[0].upper()
        input_counts[kind] += 1
        if kind == "FINAL":
            if len(parts) != 2 or parts[1].upper() != "DIRECT":
                raise ConversionError("Only FINAL,DIRECT is supported")
            final_seen = True
            expanded_counts["FINAL"] += 1
            emit("port", "0-65535", "direct", "Final direct fallback")
            continue
        if len(parts) != 3 or not all(parts):
            raise ConversionError(f"Unsupported rule syntax/flags: {line}")
        policy = parts[2].upper()
        if policy not in POLICIES:
            raise ConversionError(f"Unsupported policy: {policy}")
        if kind == "RULE-SET":
            expand_ruleset(parts[1], policy)
        else:
            convert_leaf(kind, parts[1], policy, remarks)
    if not final_seen:
        raise ConversionError("Missing FINAL,DIRECT fallback")
    if sum(expanded_counts.values()) <= 1:
        raise ConversionError("Empty routing rule list")
    metadata = {
        "schema_version": 1,
        "target": "v2rayN 7.25.6 RulesItem[] / Xray",
        "input_sha256": sha256(text),
        "input_rule_counts": dict(sorted(input_counts.items())),
        "expanded_rule_counts": dict(sorted(expanded_counts.items())),
        "emitted_match_counts": dict(sorted(emitted.items())),
        "duplicates_removed": len(duplicates),
        "duplicates": duplicates,
        "output_rule_groups": len(rules),
        "rulesets": rulesets,
        "bypass": {"source_skip_proxy": skip_proxy,
                   "additional_local_ip": list(ADDITIONAL_LOCAL_IP)},
    }
    return rules, metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DIST / "sr_top500_banlist_custom_daily.conf")
    parser.add_argument("--output", type=Path, default=DIST / "v2rayn_daily.json")
    parser.add_argument("--metadata", type=Path, default=DIST / "v2rayn_daily.meta.json")
    parser.add_argument("--ruleset-file", action="append", default=[], metavar="URL=PATH",
                        help="Use a local RULE-SET fixture; supplied mappings disable network fetching")
    args = parser.parse_args()
    overrides: dict[str, Path] = {}
    for mapping in args.ruleset_file:
        url, sep, filename = mapping.partition("=")
        if not sep or not url or not filename or url in overrides:
            parser.error("--ruleset-file requires unique URL=PATH mappings")
        overrides[url] = Path(filename)

    def loader(url: str) -> str:
        if overrides:
            if url not in overrides:
                raise ConversionError(f"No offline fixture for {url}")
            return overrides[url].read_text(encoding="utf-8-sig")
        return fetch_text(url)

    try:
        source = args.input.read_text(encoding="utf-8-sig")
        rules, metadata = convert_config(source, loader)
        rendered = json_text(rules)
        metadata["output_sha256"] = sha256(rendered)
        metadata["input_file"] = args.input.name
        # Complete conversion/validation before touching either output. CI only
        # commits after both writes and all offline/generated checks succeed.
        for path, value in ((args.output, rendered), (args.metadata, json_text(metadata))):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(value, encoding="utf-8", newline="\n")
    except (ConversionError, OSError, UnicodeError) as exc:
        parser.exit(1, f"v2rayN build failed: {exc}\n")
    print(f"OK: {args.output}: {len(rules)} groups, {sum(metadata['emitted_match_counts'].values())} matchers")
    print(f"Input counts: {metadata['input_rule_counts']}; duplicates removed: {metadata['duplicates_removed']}")


if __name__ == "__main__":
    main()
