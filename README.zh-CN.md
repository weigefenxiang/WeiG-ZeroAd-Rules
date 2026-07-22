# WeiG ZeroAd 规则

这是 **WeiG ZeroAd** 的独立规则仓库。普通广告规则按境内、境外和强度分开；
奖励广告域名始终位于独立规则包中，不会混入六个普通配置。

## 规则档位

| 地区 | 精简 | 平衡 | 严格 |
|---|---|---|---|
| 境内 | 有效的 Wei.G 基础 | Wei.G + anti-AD | Wei.G + anti-AD + 217heidai Lite |
| 境外 | HaGeZi Light 与 StevenBlack 交集 | HaGeZi Light | HaGeZi Light 与 StevenBlack 并集 |

全部境外配置都会减去完整境内目录。域名只有在连续三次每周检测中，多个 DNS
都返回 NXDOMAIN 后，才会从有效配置中剔除。

## 使用

从最新 Release 下载 `WeiG-ZeroAd-Rules.zip` 和 `SHA256SUMS`。管理器会校验
压缩包，并允许用户分别选择境内档位、境外档位和奖励广告包。

## 规则来源

[anti-AD](https://github.com/privacy-protection-tools/anti-AD) · [217heidai](https://github.com/217heidai/adblockfilters) · [HaGeZi](https://github.com/hagezi/dns-blocklists) · [StevenBlack](https://github.com/StevenBlack/hosts)

规则来源及许可证见 [SOURCES.md](SOURCES.md)。
