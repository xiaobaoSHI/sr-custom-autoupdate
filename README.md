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

## 自定义规则

编辑 `custom/rules_prepend.conf` 和 `custom/rules_privacy_prepend.conf`，然后：

```bash
python3 scripts/build.py
```

GitHub Actions 每天 UTC 00:30（北京时间 08:30）自动构建。

## 手动触发

在 GitHub → Actions → Build personalized Shadowrocket config → Run workflow 手动触发。
