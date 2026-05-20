#!/usr/bin/env python3
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

UPSTREAM_URL = "https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_top500_banlist.conf"

ROOT = Path(__file__).resolve().parents[1]
CUSTOM_DIR = ROOT / "custom"
DIST_DIR = ROOT / "dist"


DAILY_GENERAL = """[General]
# 日常稳定版：国内体验优先，国外必要网站走代理
bypass-system = true
skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com
dns-server = system,223.5.5.5,119.29.29.29
fallback-dns-server = 1.1.1.1,8.8.8.8
ipv6 = false
prefer-ipv6 = false
proxy-test-url = http://www.gstatic.com/generate_204
internet-test-url = http://www.gstatic.com/generate_204
"""


PRIVACY_GENERAL = """[General]
# 隐私检测版：BrowserLeaks / DNS Leak Test 优先
bypass-system = true
skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com
dns-server = 1.1.1.1,8.8.8.8
fallback-dns-server = 1.1.1.1,8.8.8.8
ipv6 = false
prefer-ipv6 = false
proxy-test-url = http://www.gstatic.com/generate_204
internet-test-url = http://www.gstatic.com/generate_204
"""


def fetch_text(url: str) -> str:
 req = Request(url, headers={"User-Agent": "sr-custom-autoupdate/1.0"})
 with urlopen(req, timeout=90) as resp:
  data = resp.read()
  return data.decode("utf-8-sig", errors="replace")


def extract_section(text: str, section_name: str) -> list[str]:
 pattern = re.compile(
  r"(?ms)^\[" + re.escape(section_name) + r"\]\s*\n(.*?)(?=^\[|\Z)"
 )
 match = pattern.search(text)
 if not match:
  raise RuntimeError(f"上游配置中没有找到 [{section_name}] 段")
 return match.group(1).splitlines()


def clean_rule_lines(lines: list[str]) -> list[str]:
 cleaned: list[str] = []
 seen: set[str] = set()

 for line in lines:
  raw = line.rstrip()
  s = raw.strip()

  if not s:
   continue

  if s.lower() == "[rule]":
   continue

  if s.upper().startswith("FINAL,"):
   continue

  if s.startswith("#") or s.startswith(";") or s.startswith("//"):
   cleaned.append(raw)
   continue

  key = s.upper()
  if key in seen:
   continue
  seen.add(key)
  cleaned.append(raw)

 return cleaned


def read_custom_file(path: Path) -> list[str]:
 if not path.exists():
  return []
 return clean_rule_lines(path.read_text(encoding="utf-8").splitlines())


def build_config(profile_name: str, general: str, upstream_rules: list[str], custom_files: list[str]) -> str:
 generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

 lines: list[str] = []
 lines.append(f"# Generated profile: {profile_name}")
 lines.append(f"# Generated at: {generated_at}")
 lines.append(f"# Upstream: {UPSTREAM_URL}")
 lines.append("# Do not edit files under dist/ directly. Edit custom/*.conf instead.")
 lines.append("")
 lines.append(general.strip())
 lines.append("")
 lines.append("[Rule]")

 custom_rules: list[str] = []
 for name in custom_files:
  custom_rules.extend(read_custom_file(CUSTOM_DIR / name))

 if custom_rules:
  lines.append("# ---- custom rules begin ----")
  lines.extend(custom_rules)
  lines.append("# ---- custom rules end ----")
  lines.append("")

 lines.append("# ---- upstream Johnshall rules begin ----")
 lines.extend(clean_rule_lines(upstream_rules))
 lines.append("# ---- upstream Johnshall rules end ----")
 lines.append("")
 lines.append("FINAL,DIRECT")
 lines.append("")

 return "\n".join(lines)


def main() -> None:
 DIST_DIR.mkdir(parents=True, exist_ok=True)

 upstream_text = fetch_text(UPSTREAM_URL)
 upstream_rules = extract_section(upstream_text, "Rule")

 daily = build_config(
  profile_name="daily",
  general=DAILY_GENERAL,
  upstream_rules=upstream_rules,
  custom_files=["rules_prepend.conf"],
 )

 privacy = build_config(
  profile_name="privacy",
  general=PRIVACY_GENERAL,
  upstream_rules=upstream_rules,
  custom_files=["rules_prepend.conf", "rules_privacy_prepend.conf"],
 )

 daily_path = DIST_DIR / "sr_top500_banlist_custom_daily.conf"
 privacy_path = DIST_DIR / "sr_top500_banlist_custom_privacy.conf"

 daily_path.write_text(daily, encoding="utf-8")
 privacy_path.write_text(privacy, encoding="utf-8")

 print(f"OK: wrote {daily_path} ({daily_path.stat().st_size} bytes)")
 print(f"OK: wrote {privacy_path} ({privacy_path.stat().st_size} bytes)")


if __name__ == "__main__":
 main()
