from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import os
import time
from collections import deque
from collections.abc import Callable
from pathlib import Path

import dns.asyncresolver
import dns.exception
import dns.resolver

from rule_tools.common import load_domains


RESOLVERS = (
    ("cloudflare", "1.1.1.1", 1.5, 2.2),
    ("google", "8.8.8.8", 1.5, 2.2),
    ("alidns", "223.5.5.5", 2.0, 2.8),
    ("dnspod", "119.29.29.29", 2.0, 2.8),
)
PRIMARY_RESOLVERS = ("cloudflare", "google")
CONFIRMATION_RESOLVERS = ("alidns", "dnspod")
QUERY_TYPES = ("A", "AAAA")
STATUSES = ("active", "exists", "nxdomain", "unknown")
RESOLVER_OUTCOMES = ("active", "exists", "nxdomain", "timeout", "error")
NXDOMAIN_QUORUM = 3
ResultCallback = Callable[[dict[str, object], int, int], None]


def make_resolver(
    nameserver: str, timeout: float, lifetime: float
) -> dns.asyncresolver.Resolver:
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = lifetime
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
        except dns.exception.Timeout:
            return "timeout"
        except (dns.resolver.NoNameservers, OSError):
            return "error"
    return "exists" if saw_no_answer else "error"


def retry_delay(domain: str) -> float:
    """Spread retries deterministically over 0.3-1.0 seconds."""
    value = int.from_bytes(hashlib.sha256(domain.encode("utf-8")).digest()[:2], "big")
    return 0.3 + (value / 65_535) * 0.7


def positive_status(evidence: dict[str, str]) -> str | None:
    values = set(evidence.values())
    if "active" in values:
        return "active"
    if "exists" in values:
        return "exists"
    return None


async def check_domain(
    domain: str, resolvers: dict[str, dns.asyncresolver.Resolver]
) -> tuple[str, dict[str, str], dict[str, dict[str, int]]]:
    evidence: dict[str, str] = {}
    attempts = {
        name: {outcome: 0 for outcome in RESOLVER_OUTCOMES}
        for name, *_ in RESOLVERS
    }

    async def query_group(
        names: tuple[str, ...] | list[str], stop_on_positive: bool = False
    ) -> None:
        tasks = {
            asyncio.create_task(query_one(domain, resolvers[name])): name
            for name in names
        }
        pending = set(tasks)
        while pending:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for task in done:
                name = tasks[task]
                outcome = task.result()
                evidence[name] = outcome
                attempts[name][outcome] += 1
            if stop_on_positive and positive_status(evidence):
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                return

    # Fast path for GitHub's US runners.
    await query_group(PRIMARY_RESOLVERS, stop_on_positive=True)
    positive = positive_status(evidence)
    if positive:
        return positive, evidence, attempts

    # Slower resolvers are used only to confirm unresolved/NXDOMAIN candidates.
    # A timeout is never treated as NXDOMAIN.
    await query_group(CONFIRMATION_RESOLVERS, stop_on_positive=True)
    positive = positive_status(evidence)
    if positive:
        return positive, evidence, attempts
    if sum(value == "nxdomain" for value in evidence.values()) >= NXDOMAIN_QUORUM:
        return "nxdomain", evidence, attempts

    failed = [
        name
        for name, outcome in evidence.items()
        if outcome in {"timeout", "error"}
    ]
    if failed:
        await asyncio.sleep(retry_delay(domain))
        await query_group(failed, stop_on_positive=True)
        positive = positive_status(evidence)
        if positive:
            return positive, evidence, attempts
        if sum(value == "nxdomain" for value in evidence.values()) >= NXDOMAIN_QUORUM:
            return "nxdomain", evidence, attempts
    return "unknown", evidence, attempts


async def run_checks(
    domains: list[str], concurrency: int, on_result: ResultCallback | None = None
) -> list[dict[str, object]]:
    if concurrency < 1 or concurrency > 64:
        raise ValueError("concurrency must be between 1 and 64")
    semaphore = asyncio.Semaphore(concurrency)
    resolvers = {
        name: make_resolver(address, timeout, lifetime)
        for name, address, timeout, lifetime in RESOLVERS
    }

    async def guarded(domain: str) -> dict[str, object]:
        async with semaphore:
            status, evidence, attempts = await check_domain(domain, resolvers)
            return {
                "domain": domain,
                "status": status,
                "evidence": evidence,
                "attempts": attempts,
            }

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
        self.window_seconds = 60.0
        self.samples: deque[tuple[float, int]] = deque([(self.started, 0)])
        self.resolver_outcomes = {
            name: {outcome: 0 for outcome in RESOLVER_OUTCOMES}
            for name, *_ in RESOLVERS
        }
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
        self.samples.append((now, completed))
        cutoff = now - self.window_seconds
        while len(self.samples) > 1 and self.samples[1][0] <= cutoff:
            self.samples.popleft()
        attempts = result.get("attempts", {})
        if isinstance(attempts, dict):
            for resolver_name, outcomes in attempts.items():
                if resolver_name not in self.resolver_outcomes or not isinstance(
                    outcomes, dict
                ):
                    continue
                for outcome, count in outcomes.items():
                    if outcome in self.resolver_outcomes[resolver_name]:
                        self.resolver_outcomes[resolver_name][outcome] += int(count)

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
        window_started, window_completed = self.samples[0]
        window_elapsed = max(now - window_started, 0.0)
        recent_speed = (
            (self.completed - window_completed) / window_elapsed
            if window_elapsed
            else speed
        )
        remaining = self.total - self.completed
        eta_speed = recent_speed if elapsed >= 30 and recent_speed > 0 else speed
        eta = remaining / eta_speed if eta_speed > 0 and not complete else None
        result: dict[str, object] = {
            "schema": 2,
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
            "recent_domains_per_second": round(recent_speed, 2),
            "eta_seconds": round(eta, 2) if eta is not None else None,
            "statuses": dict(self.counts),
            "resolver_outcomes": {
                name: dict(outcomes)
                for name, outcomes in self.resolver_outcomes.items()
            },
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
            f"recent={summary['recent_domains_per_second']:.1f}/s "
            f"avg={summary['domains_per_second']:.1f}/s | "
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
    resolver_outcomes = summary.get("resolver_outcomes", {})
    if not isinstance(resolver_outcomes, dict):
        resolver_outcomes = {}
    lines = [
        f"## DNS `{summary.get('input_file', 'shard')}` — {state}",
        "",
        "| Progress | Recent speed | Average speed | Elapsed | ETA | Last domain |",
        "|---:|---:|---:|---:|---:|---|",
        (
            f"| {summary.get('completed', 0):,}/{summary.get('total', 0):,} "
            f"({summary.get('progress_percent', 0)}%) | "
            f"{summary.get('recent_domains_per_second', 0)} domains/s | "
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
        "",
        "| Resolver | Active | Exists | NXDOMAIN | Timeout | Error |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, *_ in RESOLVERS:
        outcomes = resolver_outcomes.get(name, {})
        if not isinstance(outcomes, dict):
            outcomes = {}
        lines.append(
            f"| {name} | "
            + " | ".join(
                f"{int(outcomes.get(outcome, 0)):,}"
                for outcome in RESOLVER_OUTCOMES
            )
            + " |"
        )
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
    domains = sorted(
        load_domains(input_path),
        key=lambda domain: (hashlib.sha256(domain.encode("utf-8")).digest(), domain),
    )
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
