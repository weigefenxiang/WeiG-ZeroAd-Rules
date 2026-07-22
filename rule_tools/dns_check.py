from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver

from rule_tools.common import load_domains


RESOLVERS = (
    ("alidns", "223.5.5.5"),
    ("dnspod", "119.29.29.29"),
    ("cloudflare", "1.1.1.1"),
    ("google", "8.8.8.8"),
)
QUERY_TYPES = ("A", "AAAA", "CNAME")


def make_resolver(nameserver: str) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = 2.5
    resolver.lifetime = 4.0
    return resolver


async def query_one(domain: str, resolver: dns.asyncresolver.Resolver) -> str:
    saw_no_answer = False
    for query_type in QUERY_TYPES:
        try:
            answer = await resolver.resolve(domain, query_type, search=False)
            if answer.rrset is not None or str(answer.canonical_name).rstrip(".") != domain:
                return "active"
        except dns.resolver.NXDOMAIN:
            return "nxdomain"
        except dns.resolver.NoAnswer:
            saw_no_answer = True
        except (dns.resolver.NoNameservers, dns.exception.Timeout, OSError):
            return "error"
    return "exists" if saw_no_answer else "error"


async def check_domain(
    domain: str, resolvers: dict[str, dns.asyncresolver.Resolver]
) -> tuple[str, dict[str, str]]:
    primary_name = RESOLVERS[0][0]
    primary = await query_one(domain, resolvers[primary_name])
    evidence = {primary_name: primary}
    if primary in {"active", "exists"}:
        return primary, evidence

    remaining_names = [name for name, _ in RESOLVERS[1:]]
    remaining = await asyncio.gather(
        *(query_one(domain, resolvers[name]) for name in remaining_names)
    )
    evidence.update(dict(zip(remaining_names, remaining)))
    values = set(evidence.values())
    if "active" in values:
        return "active", evidence
    if "exists" in values:
        return "exists", evidence
    if values == {"nxdomain"}:
        return "nxdomain", evidence
    return "unknown", evidence


async def run_checks(domains: list[str], concurrency: int) -> list[dict[str, object]]:
    if concurrency < 1 or concurrency > 64:
        raise ValueError("concurrency must be between 1 and 64")
    semaphore = asyncio.Semaphore(concurrency)
    resolvers = {name: make_resolver(address) for name, address in RESOLVERS}

    async def guarded(domain: str) -> dict[str, object]:
        async with semaphore:
            status, evidence = await check_domain(domain, resolvers)
            return {"domain": domain, "status": status, "evidence": evidence}

    return await asyncio.gather(*(guarded(domain) for domain in domains))


def check_file(input_path: Path, output_path: Path, concurrency: int) -> dict[str, int]:
    domains = sorted(load_domains(input_path))
    results = asyncio.run(run_checks(domains, concurrency))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as stream:
        for result in results:
            stream.write(json.dumps(result, ensure_ascii=True, sort_keys=True) + "\n")
    counts: dict[str, int] = {}
    for result in results:
        status = str(result["status"])
        counts[status] = counts.get(status, 0) + 1
    return counts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, default=20)
    args = parser.parse_args()
    print(json.dumps(check_file(args.input, args.output, args.concurrency), sort_keys=True))


if __name__ == "__main__":
    main()
