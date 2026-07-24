# WeiG ZeroAd 规则

这是 **WeiG ZeroAd** 的独立规则仓库。普通广告规则按境内、境外和强度分开；
奖励广告域名始终位于独立规则包中，不会混入六个普通配置。

## 规则档位

| 地区 | 精简 | 平衡 | 严格 |
|---|---|---|---|
| 境内来源 | `Wei.G ∩ anti-AD ∩ 217heidai` | `Wei.G ∩ anti-AD` | `Wei.G ∪ anti-AD ∪ 217heidai` |
| 境外来源 | `HaGeZi ∩ StevenBlack - C` | `HaGeZi - C` | `HaGeZi ∪ StevenBlack - C` |

其中 `C = Wei.G ∪ anti-AD ∪ 217heidai`。“境内”仅表示规则来源分组，不进行
域名地域识别。全部境外配置都会减去完整的 `C`；普通配置还会排除奖励广告，
以及连续三周被多个 DNS 确认 NXDOMAIN 的域名。

## 使用

从最新 Release 下载 `WeiG-ZeroAd-Rules.zip` 和 `SHA256SUMS`。管理器会校验
压缩包，并允许用户分别选择境内档位、境外档位和奖励广告包。

## 规则来源

[anti-AD](https://github.com/privacy-protection-tools/anti-AD) · [217heidai](https://github.com/217heidai/adblockfilters) · [HaGeZi](https://github.com/hagezi/dns-blocklists) · [StevenBlack](https://github.com/StevenBlack/hosts)

规则来源及许可证见 [SOURCES.md](SOURCES.md)。
