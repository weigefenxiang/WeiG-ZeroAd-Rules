from __future__ import annotations

import argparse
import json
import time
import urllib.request
from pathlib import Path

from rule_tools.common import parse_domains, sha256_file, write_domains, write_json


MAX_SOURCE_BYTES = 64 * 1024 * 1024


def fetch(url: str, attempts: int = 3) -> str:
    error: Exception | None = None
    request = urllib.request.Request(url, headers={"User-Agent": "WeiG-ZeroAd-Rules/0.1.0"})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status}")
                data = response.read(MAX_SOURCE_BYTES + 1)
                if len(data) > MAX_SOURCE_BYTES:
                    raise RuntimeError("source exceeds 64 MiB")
                return data.decode("utf-8-sig", errors="replace")
        except Exception as exc:  # network errors vary by platform
            error = exc
            if attempt + 1 < attempts:
                time.sleep(2**attempt)
    raise RuntimeError(f"Failed to fetch {url}: {error}")


def fetch_one(root: Path, source_id: str) -> dict[str, object]:
    config = json.loads((root / "rules/sources.json").read_text(encoding="utf-8"))
    source = next((item for item in config["sources"] if item["id"] == source_id), None)
    if not source:
        raise KeyError(f"Unknown source: {source_id}")
    if source.get("type") != "remote":
        raise ValueError(f"Source {source_id} is not remote")
    text = fetch(source["url"])
    domains, parsed_entries, invalid_lines = parse_domains(text)
    minimum = int(source.get("min_domains", 1))
    maximum = int(source.get("max_domains", 2_000_000))
    if not minimum <= len(domains) <= maximum:
        raise RuntimeError(
            f"{source_id} returned {len(domains)} domains; expected {minimum}..{maximum}"
        )
    target = root / "staging/sources" / f"{source_id}.domains"
    write_domains(
        target,
        domains,
        (f"source_id={source_id}", f"source_url={source['url']}", f"rule_count={len(domains)}"),
    )
    metadata = {
        "id": source_id,
        "name": source["name"],
        "url": source["url"],
        "license": source["license"],
        "parsed_entries": parsed_entries,
        "unique_domains": len(domains),
        "duplicates_removed": max(parsed_entries - len(domains), 0),
        "invalid_lines_ignored": invalid_lines,
        "sha256": sha256_file(target),
    }
    write_json(root / "staging/source-meta" / f"{source_id}.json", metadata)
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source", required=True)
    args = parser.parse_args()
    print(json.dumps(fetch_one(args.root.resolve(), args.source), ensure_ascii=False))


if __name__ == "__main__":
    main()
