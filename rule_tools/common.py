from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path
from typing import Iterable


BLOCK_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
ADBLOCK_DOMAIN_RE = re.compile(r"^\|\|([^\^/$*]+)\^")
ASCII_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


def normalize_domain(value: str) -> str | None:
    raw = value.strip().lower().rstrip(".")
    if not raw or "://" in raw or "/" in raw or ":" in raw:
        return None
    try:
        domain = raw.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(domain) > 253 or not ASCII_DOMAIN_RE.fullmatch(domain):
        return None
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        return domain


def domains_from_line(line: str) -> set[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "!", "@@")):
        return set()

    adblock_match = ADBLOCK_DOMAIN_RE.match(stripped)
    if adblock_match:
        domain = normalize_domain(adblock_match.group(1))
        return {domain} if domain else set()

    tokens = stripped.split()
    if tokens and tokens[0] in BLOCK_IPS:
        domains = {normalize_domain(token) for token in tokens[1:]}
        return {domain for domain in domains if domain}

    domain = normalize_domain(tokens[0]) if len(tokens) == 1 else None
    return {domain} if domain else set()


def parse_domains(text: str) -> tuple[set[str], int, int]:
    domains: set[str] = set()
    parsed_entries = 0
    invalid_lines = 0
    for line in text.splitlines():
        parsed = domains_from_line(line)
        if parsed:
            parsed_entries += len(parsed)
            domains.update(parsed)
        elif line.strip() and not line.lstrip().startswith(("#", "!", "@@")):
            invalid_lines += 1
    return domains, parsed_entries, invalid_lines


def load_domains(path: Path) -> set[str]:
    if not path.is_file():
        raise FileNotFoundError(path)
    domains, _, _ = parse_domains(path.read_text(encoding="utf-8-sig"))
    return domains


def write_domains(path: Path, domains: Iterable[str], header: Iterable[str] = ()) -> None:
    normalized = sorted(set(domains))
    lines = [f"# {line}" for line in header]
    lines.extend(normalized)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def write_hosts(path: Path, domains: Iterable[str], profile: str, version: int) -> None:
    normalized = sorted(set(domains))
    lines = [
        "# WeiG ZeroAd generated hosts file. DO NOT EDIT.",
        f"# profile={profile}",
        f"# rule_version={version}",
        f"# rule_count={len(normalized)}",
        "127.0.0.1 localhost",
        "::1 localhost ip6-localhost ip6-loopback",
    ]
    lines.extend(f"0.0.0.0 {domain}" for domain in normalized)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stable_shard(domain: str, shards: int) -> int:
    return int.from_bytes(hashlib.sha256(domain.encode("ascii")).digest()[:8], "big") % shards


def load_json(path: Path, default: object | None = None) -> object:
    if not path.exists() and default is not None:
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
