from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from rule_tools.common import load_domains


# These are ownership/platform suffixes, not individual ad rules. Matching includes
# every subdomain. Files under rules/region can override or extend the built-ins.
CN_SUFFIXES = {
    "126.com",
    "163.com",
    "360.cn",
    "360.com",
    "alicdn.com",
    "alibaba.com",
    "aliyun.com",
    "baidu.com",
    "bdstatic.com",
    "bilibili.com",
    "bytedance.com",
    "douyin.com",
    "gdtimg.com",
    "gtimg.com",
    "hicloud.com",
    "hihonor.com",
    "hihonorcloud.com",
    "huawei.com",
    "iqiyi.com",
    "jd.com",
    "kuaishou.com",
    "meituan.com",
    "mi.com",
    "miui.com",
    "netease.com",
    "oppo.com",
    "pinduoduo.com",
    "qq.com",
    "qiyi.com",
    "sina.com",
    "sogou.com",
    "sohu.com",
    "taobao.com",
    "tencent.com",
    "tmall.com",
    "toutiao.com",
    "ucweb.com",
    "vivo.com",
    "weibo.com",
    "xiaomi.com",
    "ximalaya.com",
    "youku.com",
}

GLOBAL_SUFFIXES = {
    "adcolony.com",
    "adform.net",
    "admob.com",
    "adnxs.com",
    "adsrvr.org",
    "amazon-adsystem.com",
    "app-measurement.com",
    "applovin.com",
    "bing.com",
    "criteo.com",
    "criteo.net",
    "doubleclick.net",
    "facebook.com",
    "flurry.com",
    "google-analytics.com",
    "google.com",
    "googleadservices.com",
    "googlesyndication.com",
    "googletagmanager.com",
    "instagram.com",
    "ironsrc.com",
    "microsoft.com",
    "msn.com",
    "outbrain.com",
    "taboola.com",
    "unity3d.com",
    "yahoo.com",
    "yandex.com",
}


@dataclass(frozen=True)
class RegionClassification:
    cn_confirmed: set[str]
    global_confirmed: set[str]
    unknown: set[str]


def matches_suffix(domain: str, suffixes: set[str]) -> bool:
    return any(domain == suffix or domain.endswith("." + suffix) for suffix in suffixes)


def foreign_country_tld(domain: str) -> bool:
    last_label = domain.rsplit(".", 1)[-1]
    return len(last_label) == 2 and last_label.isalpha() and last_label != "cn"


def load_optional(path: Path) -> set[str]:
    return load_domains(path) if path.exists() else set()


def classify_regions(root: Path, domains: set[str]) -> RegionClassification:
    region_dir = root / "rules/region"
    manual_cn = load_optional(region_dir / "cn-overrides.domains")
    manual_global = load_optional(region_dir / "global-overrides.domains")
    overlap = manual_cn & manual_global
    if overlap:
        raise ValueError(f"Conflicting region overrides: {sorted(overlap)[:3]}")

    cn_suffixes = CN_SUFFIXES | load_optional(region_dir / "cn-suffixes.domains")
    global_suffixes = GLOBAL_SUFFIXES | load_optional(
        region_dir / "global-suffixes.domains"
    )
    cn_confirmed: set[str] = set()
    global_confirmed: set[str] = set()
    unknown: set[str] = set()

    for domain in domains:
        if domain in manual_cn:
            cn_confirmed.add(domain)
        elif domain in manual_global:
            global_confirmed.add(domain)
        elif domain.endswith(".cn") or matches_suffix(domain, cn_suffixes):
            cn_confirmed.add(domain)
        elif (
            foreign_country_tld(domain)
            or matches_suffix(domain, global_suffixes)
        ):
            global_confirmed.add(domain)
        else:
            unknown.add(domain)
    return RegionClassification(cn_confirmed, global_confirmed, unknown)


def cn_only(domains: set[str], classification: RegionClassification) -> set[str]:
    """CN(X): retain only domains positively classified as China-related."""
    return domains & classification.cn_confirmed
