from __future__ import annotations

import datetime as dt
from pathlib import Path

from rule_tools.common import load_domains, load_json, sha256_file, write_domains, write_hosts, write_json


PROFILE_NAMES = (
    "cn-lean",
    "cn-balanced",
    "cn-strict",
    "global-lean",
    "global-balanced",
    "global-strict",
)

REWARD_PACKS = (
    {
        "id": "reward.tencent",
        "file": "reward-tencent.domains",
        "title_en": "Tencent / QQ reward ads",
        "title_zh": "腾讯 / QQ 奖励广告",
    },
    {
        "id": "reward.wechat",
        "file": "reward-wechat.domains",
        "title_en": "WeChat reward ads",
        "title_zh": "微信奖励广告",
    },
    {
        "id": "reward.short-video",
        "file": "reward-short-video.domains",
        "title_en": "Short-video reward ads",
        "title_zh": "短视频奖励广告",
    },
    {
        "id": "reward.other",
        "file": "reward-other.domains",
        "title_en": "Other reward ads",
        "title_zh": "其他奖励广告",
    },
)


def reward_pack_id(domain: str) -> str:
    if domain.startswith(("wxsns", "wxa.", "wximg.", "wxsmw.")) or ".wxs.qq.com" in domain:
        return "reward.wechat"
    if any(
        value in domain
        for value in ("pangolin-sdk", "kuaishou.com", "gifshow.com", "snssdk.com", "adukwai.com")
    ):
        return "reward.short-video"
    if any(
        value in domain
        for value in (
            ".gdt.qq.com",
            ".e.qq.com",
            ".mdt.qq.com",
            ".gtimg.cn",
            ".gdtimg.com",
            "tencentmusic.com",
            ".y.qq.com",
            ".tc.qq.com",
        )
    ):
        return "reward.tencent"
    return "reward.other"


def compute_raw_profiles(
    weig: set[str],
    anti_ad: set[str],
    ad217_lite: set[str],
    hagezi_light: set[str],
    stevenblack: set[str],
    reward: set[str],
    confirmed_cn: set[str],
) -> tuple[dict[str, set[str]], set[str]]:
    cn_weig = weig & confirmed_cn
    cn_balanced = (weig | anti_ad) & confirmed_cn
    # Keep the complete regional catalog before reward/health subtraction so a
    # China-classified reward or inactive domain can never leak into global.
    cn_catalog = (weig | anti_ad | ad217_lite) & confirmed_cn
    profiles = {
        "cn-lean": cn_weig - reward,
        "cn-balanced": cn_balanced - reward,
        "cn-strict": cn_catalog - reward,
        "global-lean": (hagezi_light & stevenblack) - cn_catalog - reward,
        "global-balanced": hagezi_light - cn_catalog - reward,
        "global-strict": (hagezi_light | stevenblack) - cn_catalog - reward,
    }
    validate_profiles(profiles, reward, cn_catalog)
    return profiles, cn_catalog


def validate_profiles(
    profiles: dict[str, set[str]], reward: set[str], cn_catalog: set[str]
) -> None:
    missing = set(PROFILE_NAMES) - profiles.keys()
    if missing:
        raise ValueError(f"Missing profiles: {sorted(missing)}")
    if not profiles["cn-lean"] <= profiles["cn-balanced"] <= profiles["cn-strict"]:
        raise ValueError("Domestic profiles are not monotonic")
    if not (
        profiles["global-lean"]
        <= profiles["global-balanced"]
        <= profiles["global-strict"]
    ):
        raise ValueError("Global profiles are not monotonic")
    for name, domains in profiles.items():
        overlap = domains & reward
        if overlap:
            raise ValueError(f"Reward domains leaked into {name}: {sorted(overlap)[:3]}")
        if name.startswith("global-") and domains & cn_catalog:
            raise ValueError(f"Domestic domains leaked into {name}")


def apply_inactive(
    raw_profiles: dict[str, set[str]], inactive: set[str]
) -> dict[str, set[str]]:
    return {name: domains - inactive for name, domains in raw_profiles.items()}


def update_health_state(
    previous: dict[str, object], current_status: dict[str, str], threshold: int = 3
) -> tuple[dict[str, object], set[str]]:
    previous_streaks = previous.get("nxdomain_streaks", {})
    if not isinstance(previous_streaks, dict):
        previous_streaks = {}
    streaks: dict[str, int] = {}
    for domain, status in current_status.items():
        old = int(previous_streaks.get(domain, 0))
        if status == "nxdomain":
            streaks[domain] = old + 1
    inactive = {domain for domain, count in streaks.items() if count >= threshold}
    state = {
        "schema": 1,
        "confirmation_threshold": threshold,
        "nxdomain_streaks": dict(sorted(streaks.items())),
    }
    return state, inactive


def next_version(root: Path, date: dt.date) -> int:
    prefix = f"{date:%Y%m%d}"
    version_file = root / "rules/version.txt"
    sequence = 1
    if version_file.exists():
        current = version_file.read_text(encoding="utf-8").strip()
        if len(current) == 10 and current.startswith(prefix) and current.isdigit():
            sequence = min(int(current[-2:]) + 1, 99)
    return int(f"{prefix}{sequence:02d}")


def materialize(
    root: Path,
    raw_profiles: dict[str, set[str]],
    reward: set[str],
    current_status: dict[str, str],
    date: dt.date,
) -> dict[str, object]:
    previous = load_json(
        root / "rules/health-state.json",
        {"schema": 1, "confirmation_threshold": 3, "nxdomain_streaks": {}},
    )
    if not isinstance(previous, dict):
        raise ValueError("Invalid health-state.json")
    health_state, inactive = update_health_state(previous, current_status)
    profiles = apply_inactive(raw_profiles, inactive)
    reward = reward - inactive
    cn_catalog = raw_profiles["cn-strict"]
    validate_profiles(profiles, reward, cn_catalog)

    if len(profiles["global-strict"]) > 150_000:
        raise ValueError(
            f"Global strict exceeds the 150000 rule safety cap: "
            f"{len(profiles['global-strict'])}"
        )
    previous_manifest_path = root / "rules/generated/manifest.json"
    if previous_manifest_path.exists():
        previous_manifest = load_json(previous_manifest_path)
        if not isinstance(previous_manifest, dict):
            raise ValueError("Invalid previous manifest")
        previous_profiles = previous_manifest.get("profiles", {})
        for name, domains in profiles.items():
            region, level = name.split("-", 1)
            old_entry = previous_profiles.get(region, {}).get(level, {})
            old_count = int(old_entry.get("rules", 0)) if isinstance(old_entry, dict) else 0
            if old_count:
                ratio = abs(len(domains) - old_count) / old_count
                if ratio > 0.15:
                    raise ValueError(
                        f"{name} changed by {ratio:.1%}, above the 15% safety limit "
                        f"({old_count} -> {len(domains)})"
                    )

    version = next_version(root, date)
    generated = root / "rules/generated"
    generated.mkdir(parents=True, exist_ok=True)
    for name, domains in profiles.items():
        write_domains(
            generated / f"{name}.domains",
            domains,
            (
                "Generated by WeiG ZeroAd Rules; do not edit.",
                f"profile={name}",
                f"rule_version={version}",
                f"rule_count={len(domains)}",
            ),
        )
        write_hosts(generated / f"{name}.hosts", domains, name, version)

    write_domains(
        generated / "reward-ads.domains",
        reward,
        (
            "Independent reward-ad rules; excluded from every normal profile.",
            f"rule_version={version}",
            f"rule_count={len(reward)}",
        ),
    )
    reward_sets: dict[str, set[str]] = {pack["id"]: set() for pack in REWARD_PACKS}
    for domain in reward:
        reward_sets[reward_pack_id(domain)].add(domain)

    packs: list[dict[str, object]] = []
    for pack in REWARD_PACKS:
        domains = reward_sets[pack["id"]]
        path = generated / pack["file"]
        write_domains(
            path,
            domains,
            (
                "Independent reward-ad blocking pack.",
                f"pack_id={pack['id']}",
                f"rule_version={version}",
                f"rule_count={len(domains)}",
            ),
        )
        packs.append(
            {
                **pack,
                "type": "reward_block",
                "rules": len(domains),
                "default_enabled": True,
                "domains_sha256": sha256_file(path),
            }
        )

    profile_manifest: dict[str, dict[str, object]] = {"cn": {}, "global": {}}
    for name, domains in profiles.items():
        region, level = name.split("-", 1)
        domain_path = generated / f"{name}.domains"
        hosts_path = generated / f"{name}.hosts"
        profile_manifest[region][level] = {
            "rules": len(domains),
            "domains_file": domain_path.name,
            "hosts_file": hosts_path.name,
            "domains_sha256": sha256_file(domain_path),
            "hosts_sha256": sha256_file(hosts_path),
        }

    status_counts: dict[str, int] = {}
    for status in current_status.values():
        status_counts[status] = status_counts.get(status, 0) + 1
    health_summary = {
        "schema": 1,
        "version": version,
        "checked": len(current_status),
        "statuses": dict(sorted(status_counts.items())),
        "confirmed_inactive": len(inactive),
        "confirmation_threshold": 3,
    }
    write_json(generated / "health-summary.json", health_summary)

    manifest = {
        "schema": 3,
        "product": "WeiG-ZeroAd",
        "version": version,
        "generated_on": date.isoformat(),
        "profiles": profile_manifest,
        "reward": {
            "rules": len(reward),
            "domains_file": "reward-ads.domains",
            "domains_sha256": sha256_file(generated / "reward-ads.domains"),
        },
        "packs": packs,
        "defaults": {
            "cn_profile": "lean",
            "global_profile": "off",
            "reward_packs_enabled": [pack["id"] for pack in REWARD_PACKS],
        },
        "constraints": {
            "reward_overlap": 0,
            "cn_global_overlap": 0,
            "exact_domain_deduplication": True,
            "nxdomain_confirmation_runs": 3,
        },
        "health": health_summary,
    }
    write_json(generated / "manifest.json", manifest)
    write_json(generated / "packs.json", {"schema": 1, "version": version, "packs": packs})
    write_json(root / "rules/health-state.json", health_state)
    (root / "rules/version.txt").write_text(f"{version}\n", encoding="utf-8", newline="\n")
    reports = root / "rules/reports"
    reports.mkdir(parents=True, exist_ok=True)
    write_json(
        reports / f"{version}.json",
        {
            "schema": 1,
            "version": version,
            "profiles": {name: len(domains) for name, domains in profiles.items()},
            "reward": len(reward),
            "health": health_summary,
        },
    )
    return manifest
