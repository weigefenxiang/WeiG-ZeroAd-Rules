from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

from rule_tools.pipeline import PROFILE_NAMES, REWARD_PACKS


TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def release_files() -> tuple[str, ...]:
    profiles = tuple(f"{name}.domains" for name in PROFILE_NAMES)
    hosts = tuple(f"{name}.hosts" for name in PROFILE_NAMES)
    rewards = ("reward-ads.domains",) + tuple(pack["file"] for pack in REWARD_PACKS)
    return (
        "manifest.json",
        "packs.json",
        "health-summary.json",
        *profiles,
        *hosts,
        *rewards,
    )


def build(root: Path, output: Path) -> Path:
    generated = root / "rules/generated"
    files = release_files()
    missing = [name for name in files if not (generated / name).is_file()]
    if missing:
        raise RuntimeError("Missing generated files: " + ", ".join(missing))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in files:
            info = zipfile.ZipInfo(name, TIMESTAMP)
            info.create_system = 3
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, (generated / name).read_bytes(), compresslevel=9)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    (output.parent / "SHA256SUMS").write_text(
        f"{digest}  {output.name}\n", encoding="utf-8", newline="\n"
    )
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument(
        "--output", type=Path, default=Path("dist/WeiG-ZeroAd-Rules.zip")
    )
    args = parser.parse_args()
    root = args.root.resolve()
    output = args.output if args.output.is_absolute() else root / args.output
    print(json.dumps({"rules": str(build(root, output))}))


if __name__ == "__main__":
    main()
