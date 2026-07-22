from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path

from rule_tools.common import load_domains, load_json, write_json
from rule_tools.pipeline import PROFILE_NAMES, materialize


def load_statuses(health_dir: Path) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for path in sorted(health_dir.glob("shard-*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            domain = record["domain"]
            status = record["status"]
            if domain in statuses:
                raise ValueError(f"Duplicate DNS result for {domain}")
            statuses[domain] = status
    return statuses


def finalize(root: Path, date: dt.date) -> dict[str, object]:
    raw_profiles = {
        name: load_domains(root / "staging/profiles" / f"{name}.domains")
        for name in PROFILE_NAMES
    }
    reward = load_domains(root / "staging/reward-ads.domains")
    expected = set().union(*raw_profiles.values(), reward)
    statuses = load_statuses(root / "staging/health")
    missing = expected - statuses.keys()
    extra = statuses.keys() - expected
    if missing or extra:
        raise RuntimeError(
            f"DNS result mismatch: missing={len(missing)}, extra={len(extra)}"
        )
    manifest = materialize(root, raw_profiles, reward, statuses, date)

    source_meta: list[object] = []
    for path in sorted((root / "staging/source-meta").glob("*.json")):
        source_meta.append(load_json(path))
    write_json(
        root / "rules/sources-lock.json",
        {"schema": 1, "generated_on": date.isoformat(), "sources": source_meta},
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--date", type=dt.date.fromisoformat, default=dt.date.today())
    args = parser.parse_args()
    manifest = finalize(args.root.resolve(), args.date)
    print(json.dumps({"version": manifest["version"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
