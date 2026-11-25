# sr-custom-autoupdate

个人 Shadowrocket 配置自动生成项目。

## 上游规则

```
https://johnshall.github.io/Shadowrocket-ADBlock-Rules-Forever/sr_top500_banlist.conf
```

## 生成配置

| 文件 | 说明 |
|---|---|
| `dist/sr_top500_banlist_custom_daily.conf` | 日常稳定版：国内体验优先 |
| `dist/sr_top500_banlist_custom_privacy.conf` | 隐私检测版：BrowserLeaks / DNS Leak 优先 |
| `dist/v2rayn_daily.json` | v2rayN 7.25.6 / Xray 日常版路由规则数组 |
| `dist/v2rayn_daily.meta.json` | 转换计数、去重及来源哈希审计记录，不用于导入 |
| `dist/clash_daily.yaml` | 3X-UI / Clash Verge Rev / Mihomo 日常黑名单路由模板 |

## 自定义规则

编辑 `custom/rules_prepend.conf` 和 `custom/rules_privacy_prepend.conf`，然后：

```bash
python3 scripts/build.py
python3 scripts/build_v2rayn.py
node scripts/build_clash.mjs
node --test tests/test_clash.mjs
python3 -m unittest discover -s tests -v
```

GitHub Actions 每天 UTC 00:30（北京时间 08:30）自动构建。

## 手动触发

在 GitHub → Actions → Build personalized Shadowrocket config → Run workflow 手动触发。

## v2rayN 日常版

详见 [格式、转换语义与更新限制](docs/v2rayn.md)。原小火箭脚本、配置及 raw 地址保持不变。
新增转换器直接读取同一次构建的日常版 `.conf`，因此共用 Johnshall 黑名单和 `custom/rules_prepend.conf`；Apple News 列表在构建时下载并展开。

GitHub Actions 在同一个工作流内生成两份 `.conf`、路由 `.json` 及 Clash 路由 `.yaml`，通过测试后一起发布到 `dist/`。
PR 仅验证并上传审阅用构建产物，不提交生成文件到 main。合并后继续使用固定文件名，不需每天更换 URL。

**这里的“自动更新”指服务器端生成文件。v2rayN 7.25.6 的自定义路由 URL 导入需要手动触发，不支持该 URL 的客户端定时刷新。**
节点订阅更新周期不适用于这份路由规则。首次及后续更新都应使用路由规则设置中的 URL 导入，并完整替换旧规则；追加会留下旧规则和旧兜底。
此 PR 审阅阶段不提供 main 生产订阅地址，也不会自动导入或改动任何电脑配置。

## Clash/Mihomo 日常版（3X-UI）

固定规则 URL：`https://raw.githubusercontent.com/xiaobaoSHI/sr-custom-autoupdate/main/dist/clash_daily.yaml`。
在 3X-UI 的订阅设置 → Clash/Mihomo 中，打开启用路由，填写此 URL，远程 DNS 保持关闭，保存并重启面板；在 Clash Verge 使用规则模式并更新节点订阅，确认选择真实代理节点。
此 URL 仅为路由模板，不能当作客户端节点订阅。模板只包含 `rules`，沿用面板生成的 `PROXY` 组与各自节点，不覆盖 DNS、嗅探或节点。由同一次 daily 构建生成的 v2rayN JSON 转换，保留域名优先、IP 规则和最终 `MATCH,DIRECT`，另加两个自建节点 IP 与管理域名的直接访问例外。公共模板不包含任何订阅 ID、UUID、密钥或管理端口。
面板可能缓存远程规则；首次设置后检查客户端实际规则尾部为 `MATCH,DIRECT`（而非默认 `MATCH,PROXY`），再进行实际分流测试。生成规则超过安全体积上限、遇到未知规则或测试失败时，不发布新产物。
