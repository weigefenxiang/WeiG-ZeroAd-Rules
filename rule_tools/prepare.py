from __future__ import annotations

import argparse
import json
from pathlib import Path

from rule_tools.common import load_domains, stable_shard, write_domains, write_json
from rule_tools.pipeline import compute_raw_profiles


SOURCE_FILES = {
    "anti-ad": "anti-ad.domains",
    "217heidai-lite": "217heidai-lite.domains",
    "hagezi-light": "hagezi-light.domains",
    "stevenblack": "stevenblack.domains",
}


def prepare(root: Path, shards: int) -> dict[str, object]:
    if shards < 1 or shards > 256:
        raise ValueError("shards must be between 1 and 256")
    weig = load_domains(root / "rules/sources/owned/weig-base-20260723.domains")
    reward = load_domains(root / "rules/reward/reward-ads.domains")
    sources = {
        source_id: load_domains(root / "staging/sources" / file_name)
        for source_id, file_name in SOURCE_FILES.items()
    }
    raw_profiles, cn_catalog = compute_raw_profiles(
        weig,
        sources["anti-ad"],
        sources["217heidai-lite"],
        sources["hagezi-light"],
        sources["stevenblack"],
        reward,
    )

    profile_dir = root / "staging/profiles"
    for name, domains in raw_profiles.items():
        write_domains(profile_dir / f"{name}.domains", domains, ("Unfiltered build profile.",))
    write_domains(root / "staging/cn-catalog.domains", cn_catalog, ("Stable domestic ownership catalog.",))
    write_domains(root / "staging/reward-ads.domains", reward, ("Independent reward-ad catalog.",))

    candidates = set().union(*raw_profiles.values(), reward)
    shard_sets = [set() for _ in range(shards)]
    for domain in candidates:
        shard_sets[stable_shard(domain, shards)].add(domain)
    for index, domains in enumerate(shard_sets):
        write_domains(
            root / "staging/shards" / f"shard-{index:02d}.domains",
            domains,
            (f"shard={index}", f"shards={shards}", f"rule_count={len(domains)}"),
        )

    summary = {
        "schema": 1,
        "shards": shards,
        "candidates": len(candidates),
        "reward": len(reward),
        "cn_catalog": len(cn_catalog),
        "source_counts": {
            "weig": len(weig),
            **{name: len(domains) for name, domains in sources.items()},
        },
        "raw_profiles": {name: len(domains) for name, domains in raw_profiles.items()},
        "deduplicated_contributions": {
            "weig_base": len(weig - reward),
            "anti_ad_new": len(sources["anti-ad"] - weig - reward),
            "217heidai_new": len(
                sources["217heidai-lite"] - weig - sources["anti-ad"] - reward
            ),
            "hagezi_global_after_domestic": len(
                sources["hagezi-light"] - cn_catalog - reward
            ),
            "stevenblack_global_new": len(
                sources["stevenblack"]
                - sources["hagezi-light"]
                - cn_catalog
                - reward
            ),
        },
        "shard_counts": [len(domains) for domains in shard_sets],
    }
    write_json(root / "staging/prepare-summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--shards", type=int, default=16)
    args = parser.parse_args()
    print(json.dumps(prepare(args.root.resolve(), args.shards), ensure_ascii=False))


if __name__ == "__main__":
    main()
