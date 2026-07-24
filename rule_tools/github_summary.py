from __future__ import annotations

import argparse
import json
import os
from pathlib import Path


def load_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def append_lines(lines: list[str]) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    text = "\n".join(lines) + "\n"
    if target:
        with Path(target).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    else:
        print(text, end="")


def source_summary(path: Path) -> list[str]:
    if not path.exists():
        return [f"## Source `{path.stem}`", "", "No metadata was produced; inspect the fetch log."]
    data = load_object(path)
    valid = bool(data.get("within_expected_range", False))
    state = "accepted" if valid else "rejected by safety threshold"
    return [
        f"## Source `{data.get('id', path.stem)}` — {state}",
        "",
        "| Unique | Parsed | Duplicates removed | Invalid ignored | Expected range |",
        "|---:|---:|---:|---:|---:|",
        (
            f"| {data.get('unique_domains', 0):,} | {data.get('parsed_entries', 0):,} | "
            f"{data.get('duplicates_removed', 0):,} | {data.get('invalid_lines_ignored', 0):,} | "
            f"{data.get('expected_min_domains', 0):,}–"
            f"{data.get('expected_max_domains', 0):,} |"
        ),
        "",
        f"SHA-256: `{data.get('sha256', '-')}`",
    ]


def prepare_summary(path: Path) -> list[str]:
    data = load_object(path)
    source_counts = data.get("source_counts", {})
    profiles = data.get("raw_profiles", {})
    region = data.get("region", {})
    shard_counts = data.get("shard_counts", [])
    if (
        not isinstance(source_counts, dict)
        or not isinstance(profiles, dict)
        or not isinstance(region, dict)
    ):
        raise ValueError("Invalid prepare summary")
    if not isinstance(shard_counts, list):
        shard_counts = []
    lines = [
        "## Prepared DNS workload",
        "",
        (
            f"{data.get('candidates', 0):,} unique candidates across "
            f"{data.get('shards', 0)} shards; {data.get('reward', 0):,} reward domains."
        ),
        (
            f"Region classification: {region.get('cn_confirmed', 0):,} confirmed CN; "
            f"{region.get('global_confirmed', 0):,} confirmed global; "
            f"{region.get('unknown', 0):,} unknown (excluded from domestic profiles)."
        ),
        "",
        "| Source | Domains |",
        "|---|---:|",
    ]
    lines.extend(f"| `{name}` | {count:,} |" for name, count in sorted(source_counts.items()))
    lines.extend(("", "| Raw profile | Domains |", "|---|---:|"))
    lines.extend(f"| `{name}` | {count:,} |" for name, count in sorted(profiles.items()))
    if shard_counts:
        lines.extend(
            (
                "",
                (
                    f"Shard size: min {min(shard_counts):,}, max {max(shard_counts):,}, "
                    f"average {sum(shard_counts) / len(shard_counts):,.1f}."
                ),
            )
        )
    return lines


def release_summary(path: Path) -> list[str]:
    data = load_object(path)
    profiles = data.get("profiles", {})
    health = data.get("health", {})
    if not isinstance(profiles, dict) or not isinstance(health, dict):
        raise ValueError("Invalid release manifest")
    lines = [
        f"## Rules release `{data.get('version', '-')}`",
        "",
        "| Profile | Rules | Safety cap | Usage |",
        "|---|---:|---:|---:|",
    ]
    for region in ("cn", "global"):
        levels = profiles.get(region, {})
        if not isinstance(levels, dict):
            levels = {}
        for level in ("lean", "balanced", "strict"):
            entry = levels.get(level, {})
            if not isinstance(entry, dict):
                entry = {}
            count = int(entry.get("rules", 0))
            cap = int(entry.get("safety_cap", 0))
            usage = count / cap if cap else 0
            warning = " ⚠️" if bool(entry.get("near_safety_cap")) else ""
            lines.append(
                f"| `{region}-{level}`{warning} | {count:,} | {cap:,} | {usage:.1%} |"
            )
    statuses = health.get("statuses", {})
    if not isinstance(statuses, dict):
        statuses = {}
    lines.extend(
        (
            "",
            (
                f"Health: {health.get('checked', 0):,} checked; "
                f"active {statuses.get('active', 0):,}, exists {statuses.get('exists', 0):,}, "
                f"NXDOMAIN {statuses.get('nxdomain', 0):,}, unknown "
                f"{statuses.get('unknown', 0):,}; confirmed inactive "
                f"{health.get('confirmed_inactive', 0):,}."
            ),
            (
                f"Independent reward rules: {data.get('reward', {}).get('rules', 0):,} / "
                f"{data.get('reward', {}).get('safety_cap', 0):,}."
            ),
        )
    )
    if any(
        isinstance(entry, dict) and bool(entry.get("near_safety_cap"))
        for levels in profiles.values() if isinstance(levels, dict)
        for entry in levels.values()
    ) or bool(data.get("reward", {}).get("near_safety_cap")):
        lines.extend(("", "⚠️ One or more rule sets use at least 80% of their safety cap."))
    return lines


def main() -> None:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--source", type=Path)
    group.add_argument("--prepare", type=Path)
    group.add_argument("--release", type=Path)
    args = parser.parse_args()
    if args.source:
        lines = source_summary(args.source)
    elif args.prepare:
        lines = prepare_summary(args.prepare)
    else:
        lines = release_summary(args.release)
    append_lines(lines)


if __name__ == "__main__":
    main()
