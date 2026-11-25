#!/usr/bin/env node
// Convert the already validated v2rayN daily snapshot; do not fetch new sources.
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

export function convertRules(groups) {
  if (!Array.isArray(groups) || groups.length < 2) throw Error("Expected nonempty daily RulesItem array");
  const actions = {proxy:"PROXY", direct:"DIRECT", block:"REJECT"};
  const types = {full:"DOMAIN",domain:"DOMAIN-SUFFIX",keyword:"DOMAIN-KEYWORD",regexp:"DOMAIN-REGEX"};
  const allowed = new Set(["remarks","enabled","outboundTag","domain","ip","port"]);
  // Subscription endpoints must remain reachable directly. IP rules here use
  // no-resolve to avoid DNS lookups before checking the blacklist domains.
  const rules = [
    "DOMAIN,ai.172flying.com,DIRECT",
    "IP-CIDR,23.238.39.237/32,DIRECT,no-resolve",
    "IP-CIDR,204.141.236.16/32,DIRECT,no-resolve"
  ];
  const seen = new Set(rules);
  const emit = line => { if (!seen.has(line)) { seen.add(line); rules.push(line); } };
  let count = 0;
  for (const [i,group] of groups.entries()) {
    if (!group || typeof group !== "object" || Array.isArray(group) ||
        Object.keys(group).some(k=>!allowed.has(k)) || group.enabled !== true ||
        !Object.hasOwn(actions,group.outboundTag)) throw Error("Unexpected daily routing group at "+i);
    const action = actions[group.outboundTag];
    const fields = ["domain","ip","port"].filter(k=>Object.hasOwn(group,k));
    if (fields.length !== 1) throw Error("Expected exactly one condition at "+i);
    const field = fields[0], value = group[field];
    if (field === "port") {
      if (i !== groups.length-1 || value !== "0-65535" || action !== "DIRECT")
        throw Error("Only the last full-port DIRECT fallback is supported");
      emit("MATCH,DIRECT");
      continue;
    }
    if (i === groups.length-1 || !Array.isArray(value) || !value.length)
      throw Error("Missing final fallback or empty matcher group");
    for (const item of value) {
      if (typeof item !== "string") throw Error("Matcher must be a string");
      if (field === "domain") {
        const n = item.indexOf(":");
        const prefix = item.slice(0,n), v = item.slice(n+1);
        if (n < 1 || !Object.hasOwn(types,prefix)) throw Error("Unsupported domain matcher: "+item);
        if (prefix === "regexp" ? v !== "^.+\\.local$" :
            !/^[a-z0-9_.-]+$/.test(v) || v.startsWith(".") || v.endsWith(".") || v.includes(".."))
          throw Error("Unexpected domain syntax: "+item);
        emit(types[prefix]+","+v+","+action);
      } else {
        // IP networks have already been normalized/validated by build_v2rayn.py.
        // Reject malformed strings and any extra flags/predicates here.
        const m = /^([0-9a-f:.]+)\/(\d{1,3})$/.exec(item);
        if (!m) throw Error("Invalid CIDR: "+item);
        const v6 = m[1].includes(":");
        if (+m[2] > (v6?128:32) || (!v6 &&
            (!/^\d{1,3}(\.\d{1,3}){3}$/.test(m[1]) || m[1].split(".").some(n=>+n>255))))
          throw Error("Invalid CIDR: "+item);
        emit((v6?"IP-CIDR6":"IP-CIDR")+","+item+","+action);
      }
      count++;
    }
  }
  if (!count || rules.at(-1)!=="MATCH,DIRECT" || !rules.some(r=>r.endsWith(",PROXY")))
    throw Error("Missing daily blacklist or final DIRECT");
  return rules;
}

export function renderRules(rules) {
  // JSON double-quoted strings are valid YAML scalars; no YAML dependency.
  const result = "# Generated from dist/v2rayn_daily.json; do not edit.\n# 3X-UI routing only: keep panel-generated nodes and PROXY group.\nrules:\n"+rules.map(r=>"  - "+JSON.stringify(r)+"\n").join("");
  // 3X-UI v3.7.0 remote routing input limit is 2 MiB.
  // Keep a margin below it to fail closed as the upstream grows.
  if (result.length > 1900000 || /[^\x00-\x7f]/.test(result))
    throw Error("Remote routing YAML exceeds safe size budget or contains non-ASCII");
  return result;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const input = fileURLToPath(new URL("../dist/v2rayn_daily.json", import.meta.url));
  const output = fileURLToPath(new URL("../dist/clash_daily.yaml", import.meta.url));
  const rules = convertRules(JSON.parse(readFileSync(input, "utf8")));
  const text = renderRules(rules);
  writeFileSync(output + ".tmp", text, "utf8");
  renameSync(output + ".tmp", output);
  console.log("OK: "+rules.length+" rules, "+text.length+" bytes");
}
