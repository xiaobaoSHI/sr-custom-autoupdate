# v2rayN 7.25.6 / Xray 日常路由规则

本功能只增加路由产物 `dist/v2rayn_daily.json`，不改变 `scripts/build.py`、自定义源文件或两份 Shadowrocket 配置的生成逻辑。
转换器读取旧脚本刚生成的 `dist/sr_top500_banlist_custom_daily.conf`，不会重新下载另一份 Johnshall 黑名单。
因此小火箭与 v2rayN 共用同一次上游快照和 `custom/rules_prepend.conf`，不另行维护名单。
Apple News 则在每次构建时展开其当前远程列表；小火箭仍保留原有远程引用。

## 格式与优先级

产物顶层为 `RulesItem[]` JSON 数组，不是完整 Xray 配置，也不是节点订阅。
仅使用 `type`、`remarks`、`enabled`、`outboundTag` 及 `domain` / `ip` / `port` 等路由字段。
v2rayN 7.25.6 的实际 [RulesItem 类](https://github.com/2dust/v2rayN/blob/7.25.6/v2rayN/ServiceLib/Models/Entities/RulesItem.cs) 中，域名/IP 为字符串数组，端口/出站为字符串；`enabled` 缺省为 true，导入时重建规则 ID。

顺序固定为：

1. 日常配置 `skip-proxy` 的私网、`localhost`、`*.local`、`captive.apple.com` 直连旁路。
2. 补全本地回环/链路本地/IPv6 ULA 旁路：`127.0.0.0/8`、`169.254.0.0/16`、`::1/128`、`fe80::/10`、`fc00::/7`。这是局域网绕过路由，不启用、禁用或拒绝 IPv6。
3. 四个自定义检测站（browserleaks.com、ipleak.net、dnsleaktest.com、test-ipv6.com），保持自定义文件原顺序及出站。
4. Johnshall 上游规则，按源文件顺序；远程 Apple News 在引用所在位置展开。
5. 唯一的最终直连：`{"port":"0-65535","outboundTag":"direct"}`。

| 源规则 | JSON 条件 | 语义 |
|---|---|---|
| `DOMAIN` | `full:域名` | 精确匹配，不包括子域 |
| `DOMAIN-SUFFIX` | `domain:域名` | 本域及其子域，不误匹配相似后缀 |
| `DOMAIN-KEYWORD` | `keyword:关键词` | 子串匹配，amazon.cn 也命中 amazon |
| `IP-CIDR` / `IP-CIDR6` | `ip` 数组 | 保留 IPv4 / IPv6 CIDR |
| Apple News `RULE-SET` | 在原位置展开 | 当前为两个 `DOMAIN`，继承引用的出站 |
| `FINAL,DIRECT` | 全端口 direct | 未命中名单的流量直连 |

Xray [官方路由文档](https://xtls.github.io/config/routing.html)规定自上而下第一条命中生效；同一规则的多个条件是 AND。
因此 JSON 分开输出域名/IP，仅合并相邻且条件类型、优先级来源、出站相同的规则；精确重复项保留首次出现，不按类型全局重排。
`*.local` 使用仅匹配子域的正则，`localhost` 和 `captive.apple.com` 使用精确匹配。

未知规则/动作、不支持的参数（包括无法逐条表达的 `no-resolve`）、未知远程 RULE-SET、空或损坏远程列表、缺失或非最后的 `FINAL,DIRECT` 都会让构建失败，阻止发布不完整名单。
`dist/v2rayn_daily.meta.json` 记录输入哈希、远程列表哈希、原始计数、展开与去重计数。它不是导入文件。

## 更新机制和手动导入限制

同一个 GitHub Actions 工作流保留每日 UTC 00:30（北京时间 08:30）计划；实际执行可能延后。
先运行原 `build.py`，再转换 JSON，测试全部通过后才在 main 同一提交发布两份 `.conf`、JSON 和审计文件。
PR 工作流只验证、上传构建产物，不向 main 推送；合并后生成文件名保持稳定，raw 地址路径不随日期改变。
main 生产 URL 等审阅合并后再提供。本分支的 raw 文件仅作审阅预览。

**v2rayN 7.25.6 不会按周期自动拉取这份路由 URL。**
[路由 URL 导入源码](https://github.com/2dust/v2rayN/blob/7.25.6/v2rayN/ServiceLib/ViewModels/RoutingRuleSettingViewModel.cs) 是用户命令触发下载、解析 `List<RulesItem>`。
[后台定时任务](https://github.com/2dust/v2rayN/blob/7.25.6/v2rayN/ServiceLib/Manager/TaskManager.cs) 更新节点 `SubItems` 和 Geo 数据，没有调用路由 URL 导入；
[RoutingItem](https://github.com/2dust/v2rayN/blob/7.25.6/v2rayN/ServiceLib/Models/Entities/RoutingItem.cs) 也没有路由刷新周期字段。
所以服务器定时生成与客户端自动订阅不能混为一谈；设置节点订阅更新间隔不会刷新此文件。

审阅合并后，用户可在路由设置新建独立规则集、填写路由 URL，使用“从订阅 Url 中导入规则”。
再次导入时，“是否追加规则？”选 **否（全部替换）**，检查后保存并选择所需活动规则集。不要导入节点订阅入口。
追加会保留旧代理名单和旧最终直连规则，后面的新规则可能永远无法生效。
本 PR 不自动导入、不启用规则、不修改电脑配置，也不安装定时脚本。

## DNS、IPv6 与验证边界

JSON 不包含 DNS、`domainStrategy`、IPv6 开关、嗅探或 TUN 设置；不移植 Shadowrocket General 的 DNS/IPv6 策略，也不移植隐私版的 IPv6 拒绝规则。
保留 IPv6 CIDR 和本地旁路不等于修改 IPv6 开关。
现有客户端的域名可见性和 DNS 路由策略仍会影响实际匹配：只有 IP 而无域名时不能命中域名规则；`IPOnDemand` 可能先解析域名并命中 IP 规则。
[v2rayN 生成 Xray 路由的代码](https://github.com/2dust/v2rayN/blob/7.25.6/v2rayN/ServiceLib/Services/CoreConfig/V2ray/V2rayRoutingService.cs) 会保留客户端的路由解析策略，并可能在 TUN 下插入系统 DNS/进程规则。因此这里保证的是用户规则集内部顺序，不覆盖客户端已有的系统规则。

自动测试包含解析、格式/字段类型、计数守恒、重复项、精确域名/后缀/关键词/IP、Apple News 展开、来源失败及独立首条匹配模拟。
关键行为：四站、google、amazon.cn、Apple News 与命中的代理 IP 走代理，baidu.com、未命中站点、局域网地址直连。
这些测试不替代实际节点连通、DNS 泄漏或 TUN 端到端检查；本任务未在用户电脑导入规则或进行这些联网检查。

## 本地复现

```sh
python scripts/build.py
python scripts/build_v2rayn.py
python -m unittest discover -s tests -v
```

仅复现已有 daily 快照时，不需重跑旧构建；可用转换器的 `--ruleset-file URL=PATH` 指定 Apple News 本地快照，以离线验证并避免上游随时间变化。
