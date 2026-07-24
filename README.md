# WeiG ZeroAd Rules

Small, reproducible DNS/hosts rule releases for **WeiG ZeroAd**. Normal ad
profiles are separated by region and strength. Reward-ad endpoints are always
kept in independent, user-controlled packs.

[简体中文](README.zh-CN.md)

## Profiles

| Region | Lean | Balanced | Strict |
|---|---|---|---|
| Domestic sources | `Wei.G ∩ anti-AD ∩ 217heidai` | `Wei.G ∩ anti-AD` | `Wei.G ∪ anti-AD ∪ 217heidai` |
| Global sources | `HaGeZi ∩ StevenBlack - C` | `HaGeZi - C` | `HaGeZi ∪ StevenBlack - C` |

Here `C = Wei.G ∪ anti-AD ∪ 217heidai`. “Domestic” describes the source group;
no geographic domain classifier is applied. Every global profile excludes the
complete `C` catalog. Every normal profile excludes reward-ad domains and
domains confirmed inactive by three consecutive weekly multi-resolver
NXDOMAIN runs.

## Use

Download `WeiG-ZeroAd-Rules.zip` and `SHA256SUMS` from the latest Release. The
WeiG ZeroAd manager verifies the archive and lets users select one domestic
profile, an optional global profile, and independent reward-ad packs.

## Build

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

The weekly workflow downloads upstreams in parallel, splits DNS checks across
16 jobs, verifies set invariants, and publishes a data-only release.

## Sources

[anti-AD](https://github.com/privacy-protection-tools/anti-AD) · [217heidai](https://github.com/217heidai/adblockfilters) · [HaGeZi](https://github.com/hagezi/dns-blocklists) · [StevenBlack](https://github.com/StevenBlack/hosts)

See [SOURCES.md](SOURCES.md) for attribution and licenses.
