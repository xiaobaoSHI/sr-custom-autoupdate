import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { convertRules, renderRules } from "../scripts/build_clash.mjs";

const fixture = [
 {enabled:true,outboundTag:"direct",domain:["full:localhost","regexp:^.+\\.local$"]},
 {enabled:true,outboundTag:"proxy",domain:["domain:google.com","keyword:amazon","full:news.example"]},
 {enabled:true,outboundTag:"block",domain:["full:ads.example"]},
 {enabled:true,outboundTag:"direct",ip:["192.168.0.0/16","::1/128"]},
 {enabled:true,outboundTag:"proxy",ip:["91.108.56.0/22"]},
 {enabled:true,outboundTag:"direct",port:"0-65535"}
];
test("same order and policy; explicit direct endpoint exceptions",()=>{
 const r=convertRules(fixture);
 assert.deepEqual(r.slice(0,3),["DOMAIN,ai.172flying.com,DIRECT","IP-CIDR,23.238.39.237/32,DIRECT,no-resolve","IP-CIDR,204.141.236.16/32,DIRECT,no-resolve"]);
 assert.deepEqual(r.slice(3),["DOMAIN,localhost,DIRECT","DOMAIN-REGEX,^.+\\.local$,DIRECT","DOMAIN-SUFFIX,google.com,PROXY","DOMAIN-KEYWORD,amazon,PROXY","DOMAIN,news.example,PROXY","DOMAIN,ads.example,REJECT","IP-CIDR,192.168.0.0/16,DIRECT","IP-CIDR6,::1/128,DIRECT","IP-CIDR,91.108.56.0/22,PROXY","MATCH,DIRECT"]);
 assert.deepEqual(renderRules(r).split("\n").filter(x=>x.startsWith("  - ")).map(x=>JSON.parse(x.slice(4))),r);
});
test("fail closed on missing fallback, unknown predicates/actions and malformed domains",()=>{
 assert.throws(()=>convertRules(fixture.slice(0,-1)));
 assert.throws(()=>convertRules([{...fixture[1],port:"443"},...fixture.slice(2)]));
 assert.throws(()=>convertRules([{...fixture[1],outboundTag:"unknown"},...fixture.slice(2)]));
 assert.throws(()=>convertRules([{...fixture[1],domain:["geosite:cn"]},...fixture.slice(2)]));
 assert.throws(()=>convertRules([{...fixture[1],domain:["domain:evil,PROXY"]},...fixture.slice(2)]));
 assert.throws(()=>convertRules([{...fixture[1],domain:["regexp:.*"]},...fixture.slice(2)]));
});
test("current daily artifact is deterministic, preserves source count, no node or DNS override",()=>{
 const source=JSON.parse(readFileSync(new URL("../dist/v2rayn_daily.json",import.meta.url),"utf8"));
 const rules=convertRules(source), rendered=renderRules(rules);
 assert.equal(readFileSync(new URL("../dist/clash_daily.yaml",import.meta.url),"utf8"),rendered);
 assert.ok(rules.length>1000);
 const count=source.reduce((n,g)=>n+(g.domain?.length??g.ip?.length??1),0);
 // Exact duplicate direct exceptions, if they appear upstream, can reduce the count.
 assert.ok(rules.length>=count && rules.length<=count+3);
 assert.equal(rules.at(-1),"MATCH,DIRECT");
 assert.equal(rules.filter(r=>r.startsWith("MATCH,")).length,1);
 assert.ok(!/^\s*(proxies|proxy-groups|dns|sniffer|proxy-providers):/m.test(rendered));
 assert.ok(Buffer.byteLength(rendered)<1900001);
 const domainRoute= function domainRoute(host, rules) {
 for(const line of rules){const [type,v,action]=line.split(","); if(type==="MATCH")return v;if(type==="DOMAIN"&&host===v || type==="DOMAIN-SUFFIX"&&(host===v||host.endsWith("."+v)) || type==="DOMAIN-KEYWORD"&&host.includes(v) || type==="DOMAIN-REGEX"&&new RegExp(v).test(host))return action;}
};
 for (const [host,action] of Object.entries({"www.google.com":"PROXY","www.youtube.com":"PROXY","browserleaks.com":"PROXY","www.dnsleaktest.com":"PROXY","baidu.com":"DIRECT","localhost":"DIRECT","printer.local":"DIRECT","ai.172flying.com":"DIRECT","test-unlisted-172fly.example":"DIRECT"})) assert.equal(domainRoute(host,rules),action,host);
});
