from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import time
from collections.abc import Callable
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
STATUSES = ("active", "exists", "nxdomain", "unknown")
ResultCallback = Callable[[dict[str, object], int, int], None]


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


async def run_checks(
    domains: list[str], concurrency: int, on_result: ResultCallback | None = None
) -> list[dict[str, object]]:
    if concurrency < 1 or concurrency > 64:
        raise ValueError("concurrency must be between 1 and 64")
    semaphore = asyncio.Semaphore(concurrency)
    resolvers = {name: make_resolver(address) for name, address in RESOLVERS}

    async def guarded(domain: str) -> dict[str, object]:
        async with semaphore:
            status, evidence = await check_domain(domain, resolvers)
            return {"domain": domain, "status": status, "evidence": evidence}

    tasks = [asyncio.create_task(guarded(domain)) for domain in domains]
    results: list[dict[str, object]] = []
    for task in asyncio.as_completed(tasks):
        result = await task
        results.append(result)
        if on_result is not None:
            on_result(result, len(results), len(domains))
    return sorted(results, key=lambda item: str(item["domain"]))


def format_duration(seconds: float | None) -> str:
    if seconds is None or not math.isfinite(seconds):
        return "--"
    seconds = max(int(seconds), 0)
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{seconds:02d}s"
    return f"{seconds}s"


class ProgressReporter:
    def __init__(
        self,
        input_path: Path,
        output_path: Path,
        summary_path: Path,
        stream: object,
        total: int,
        concurrency: int,
        progress_seconds: float,
        progress_steps: int,
    ) -> None:
        self.input_path = input_path
        self.output_path = output_path
        self.summary_path = summary_path
        self.stream = stream
        self.total = total
        self.concurrency = concurrency
        self.progress_seconds = progress_seconds
        self.counts = {status: 0 for status in STATUSES}
        self.completed = 0
        self.last_domain = ""
        self.started = time.monotonic()
        self.last_log = self.started
        self.step_size = max(1, math.ceil(max(total, 1) / max(progress_steps, 1)))
        self.next_step = self.step_size

    def start(self) -> None:
        print(
            f"[dns] starting total={self.total:,} concurrency={self.concurrency}",
            flush=True,
        )
        self.write_summary(complete=False)

    def record(self, result: dict[str, object], completed: int, total: int) -> None:
        line = json.dumps(result, ensure_ascii=True, sort_keys=True) + "\n"
        self.stream.write(line)  # type: ignore[attr-defined]
        self.stream.flush()  # type: ignore[attr-defined]
        self.completed = completed
        self.total = total
        self.last_domain = str(result["domain"])
        status = str(result["status"])
        self.counts[status] = self.counts.get(status, 0) + 1

        now = time.monotonic()
        should_log = (
            completed == total
            or completed >= self.next_step
            or now - self.last_log >= self.progress_seconds
        )
        if not should_log:
            return
        while self.next_step <= completed:
            self.next_step += self.step_size
        self.last_log = now
        self.log_progress(now)
        self.write_summary(complete=False, now=now)

    def snapshot(
        self,
        complete: bool,
        error: str | None = None,
        now: float | None = None,
    ) -> dict[str, object]:
        now = time.monotonic() if now is None else now
        elapsed = max(now - self.started, 0.0)
        speed = self.completed / elapsed if elapsed else 0.0
        remaining = self.total - self.completed
        eta = remaining / speed if speed > 0 and not complete else None
        result: dict[str, object] = {
            "schema": 1,
            "complete": complete,
            "input_file": self.input_path.name,
            "output_file": self.output_path.name,
            "total": self.total,
            "completed": self.completed,
            "progress_percent": round(
                (self.completed / self.total * 100) if self.total else 100, 2
            ),
            "concurrency": self.concurrency,
            "elapsed_seconds": round(elapsed, 2),
            "domains_per_second": round(speed, 2),
            "eta_seconds": round(eta, 2) if eta is not None else None,
            "statuses": dict(self.counts),
            "last_domain": self.last_domain or None,
        }
        if error:
            result["error"] = error
        return result

    def write_summary(
        self, complete: bool, error: str | None = None, now: float | None = None
    ) -> dict[str, object]:
        summary = self.snapshot(complete, error, now)
        self.summary_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.summary_path.with_name(self.summary_path.name + ".tmp")
        temporary.write_text(
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.summary_path)
        return summary

    def log_progress(self, now: float | None = None) -> None:
        summary = self.snapshot(complete=False, now=now)
        statuses = summary["statuses"]
        assert isinstance(statuses, dict)
        print(
            "[dns] "
            f"{self.completed:,}/{self.total:,} ({summary['progress_percent']:.1f}%) | "
            f"{summary['domains_per_second']:.1f} domains/s | "
            f"ETA {format_duration(summary['eta_seconds'])} | "
            + " ".join(f"{name}={statuses.get(name, 0):,}" for name in STATUSES)
            + f" | last={self.last_domain}",
            flush=True,
        )


def append_github_summary(summary: dict[str, object]) -> None:
    target = os.environ.get("GITHUB_STEP_SUMMARY")
    if not target:
        return
    statuses = summary.get("statuses", {})
    if not isinstance(statuses, dict):
        statuses = {}
    state = "Completed" if summary.get("complete") else "Incomplete / failed"
    lines = [
        f"## DNS `{summary.get('input_file', 'shard')}` — {state}",
        "",
        "| Progress | Speed | Elapsed | ETA | Last domain |",
        "|---:|---:|---:|---:|---|",
        (
            f"| {summary.get('completed', 0):,}/{summary.get('total', 0):,} "
            f"({summary.get('progress_percent', 0)}%) | "
            f"{summary.get('domains_per_second', 0)} domains/s | "
            f"{format_duration(float(summary.get('elapsed_seconds', 0)))} | "
            f"{format_duration(summary.get('eta_seconds'))} | "
            f"`{summary.get('last_domain') or '-'}` |"
        ),
        "",
        "| Active | Exists | NXDOMAIN | Unknown |",
        "|---:|---:|---:|---:|",
        (
            f"| {statuses.get('active', 0):,} | {statuses.get('exists', 0):,} | "
            f"{statuses.get('nxdomain', 0):,} | {statuses.get('unknown', 0):,} |"
        ),
    ]
    if summary.get("error"):
        lines.extend(("", f"Error: `{summary['error']}`"))
    with Path(target).open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(lines) + "\n")


def check_file(
    input_path: Path,
    output_path: Path,
    concurrency: int,
    summary_path: Path | None = None,
    progress_seconds: float = 30.0,
    progress_steps: int = 20,
) -> dict[str, int]:
    domains = sorted(load_domains(input_path))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path = summary_path or output_path.with_suffix(".summary.json")

    with output_path.open("w", encoding="utf-8", newline="\n") as stream:
        reporter = ProgressReporter(
            input_path,
            output_path,
            summary_path,
            stream,
            len(domains),
            concurrency,
            progress_seconds,
            progress_steps,
        )
        reporter.start()
        try:
            results = asyncio.run(run_checks(domains, concurrency, reporter.record))
        except BaseException as exc:
            message = f"{type(exc).__name__}: {exc}".replace("\n", " ")
            summary = reporter.write_summary(complete=False, error=message)
            print(
                f"[dns] FAILED completed={reporter.completed:,}/{reporter.total:,} "
                f"last={reporter.last_domain or '-'} error={message}",
                flush=True,
            )
            append_github_summary(summary)
            if os.environ.get("GITHUB_ACTIONS") == "true":
                print(
                    f"::error title=DNS check failed::{reporter.completed}/{reporter.total} "
                    f"complete; last={reporter.last_domain or '-'}; {message}",
                    flush=True,
                )
            raise

    # The file is useful while a job is running; sort it after success for reproducible output.
    with output_path.open("w", encoding="utf-8", newline="\n") as stream:
        for result in results:
            stream.write(json.dumps(result, ensure_ascii=True, sort_keys=True) + "\n")
    summary = reporter.write_summary(complete=True)
    append_github_summary(summary)
    return {status: reporter.counts.get(status, 0) for status in STATUSES}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--concurrency", type=int, default=20)
    parser.add_argument("--progress-seconds", type=float, default=30.0)
    parser.add_argument("--progress-steps", type=int, default=20)
    args = parser.parse_args()
    counts = check_file(
        args.input,
        args.output,
        args.concurrency,
        args.summary,
        args.progress_seconds,
        args.progress_steps,
    )
    print(json.dumps(counts, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
