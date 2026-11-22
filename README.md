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

## 自定义规则

编辑 `custom/rules_prepend.conf` 和 `custom/rules_privacy_prepend.conf`，然后：

```bash
python3 scripts/build.py
python3 scripts/build_v2rayn.py
python3 -m unittest discover -s tests -v
```

GitHub Actions 每天 UTC 00:30（北京时间 08:30）自动构建。

## 手动触发

在 GitHub → Actions → Build personalized Shadowrocket config → Run workflow 手动触发。

## v2rayN 日常版

详见 [格式、转换语义与更新限制](docs/v2rayn.md)。原小火箭脚本、配置及 raw 地址保持不变。
新增转换器直接读取同一次构建的日常版 `.conf`，因此共用 Johnshall 黑名单和 `custom/rules_prepend.conf`；Apple News 列表在构建时下载并展开。

GitHub Actions 在同一个工作流内生成两份 `.conf` 和一份路由 `.json`，通过测试后一起发布到 `dist/`。
PR 仅验证并上传审阅用构建产物，不提交生成文件到 main。合并后继续使用固定文件名，不需每天更换 URL。

**这里的“自动更新”指服务器端生成文件。v2rayN 7.25.6 的自定义路由 URL 导入需要手动触发，不支持该 URL 的客户端定时刷新。**
节点订阅更新周期不适用于这份路由规则。首次及后续更新都应使用路由规则设置中的 URL 导入，并完整替换旧规则；追加会留下旧规则和旧兜底。
此 PR 审阅阶段不提供 main 生产订阅地址，也不会自动导入或改动任何电脑配置。
