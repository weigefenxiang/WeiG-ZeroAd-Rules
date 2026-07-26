from __future__ import annotations

import asyncio
import datetime as dt
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rule_tools.build_release import build, release_files
from rule_tools.common import domains_from_line, load_domains, normalize_domain
from rule_tools.fetch_source import fetch_one
from rule_tools.pipeline import (
    PROFILE_RULE_CAPS,
    PROFILE_NAMES,
    apply_inactive,
    compute_raw_profiles,
    materialize,
    update_health_state,
    validate_rule_caps,
)
from rule_tools.prepare import prepare


ROOT = Path(__file__).resolve().parents[1]
DNSPYTHON_AVAILABLE = importlib.util.find_spec("dns") is not None


class ParsingTests(unittest.TestCase):
    def test_normalizes_domains_and_idn(self) -> None:
        self.assertEqual(normalize_domain("SDK.E.QQ.COM."), "sdk.e.qq.com")
        self.assertEqual(normalize_domain("广告.example"), "xn--4rr70v.example")
        self.assertIsNone(normalize_domain("*.example.com"))
        self.assertIsNone(normalize_domain("https://example.com/path"))
        self.assertIsNone(normalize_domain("127.0.0.1"))

    def test_supported_formats_ignore_allow_rules(self) -> None:
        self.assertEqual(domains_from_line("0.0.0.0 ads.example.com"), {"ads.example.com"})
        self.assertEqual(domains_from_line("||ads.example.com^"), {"ads.example.com"})
        self.assertEqual(domains_from_line("@@||safe.example.com^"), set())


class SetAlgebraTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reward = {"reward.cn", "reward.global"}
        self.weig = {"base.cn", "shared.cn", "consensus.cn", "reward.cn"}
        self.anti = {"shared.cn", "consensus.cn", "anti.cn", "cross.example", "reward.cn"}
        self.ad217 = {"consensus.cn", "strict.cn", "cross.example", "global-overlap.example"}
        self.hagezi = {"global-overlap.example", "cross.example", "hagezi.global", "both.global"}
        self.steven = {"steven.global", "both.global", "reward.global"}
        self.profiles, self.cn_catalog = compute_raw_profiles(
            self.weig,
            self.anti,
            self.ad217,
            self.hagezi,
            self.steven,
            self.reward,
        )

    def test_profiles_are_monotonic(self) -> None:
        self.assertLessEqual(self.profiles["cn-lean"], self.profiles["cn-balanced"])
        self.assertLessEqual(self.profiles["cn-balanced"], self.profiles["cn-strict"])
        self.assertLessEqual(self.profiles["global-lean"], self.profiles["global-balanced"])
        self.assertLessEqual(self.profiles["global-balanced"], self.profiles["global-strict"])

    def test_regions_and_reward_are_disjoint(self) -> None:
        for name, domains in self.profiles.items():
            self.assertFalse(domains & self.reward, name)
            if name.startswith("global-"):
                self.assertFalse(domains & self.cn_catalog, name)

    def test_expected_profile_meaning(self) -> None:
        self.assertEqual(self.profiles["cn-lean"], {"consensus.cn"})
        self.assertIn("shared.cn", self.profiles["cn-balanced"])
        self.assertNotIn("base.cn", self.profiles["cn-balanced"])
        self.assertNotIn("anti.cn", self.profiles["cn-balanced"])
        self.assertIn("anti.cn", self.profiles["cn-strict"])
        self.assertIn("strict.cn", self.profiles["cn-strict"])
        self.assertEqual(self.profiles["global-lean"], {"both.global"})
        self.assertIn("hagezi.global", self.profiles["global-balanced"])
        self.assertIn("steven.global", self.profiles["global-strict"])

    def test_inactive_is_removed_from_every_profile(self) -> None:
        filtered = apply_inactive(self.profiles, {"consensus.cn", "both.global"})
        self.assertNotIn("consensus.cn", filtered["cn-lean"])
        self.assertNotIn("both.global", filtered["global-strict"])

    def test_complete_wad_catalog_is_excluded_from_global_profiles(self) -> None:
        profiles, cn_catalog = compute_raw_profiles(
            {"shared.example", "unknown.example"},
            {"shared.example", "unknown.example"},
            {"shared.example", "unknown.example"},
            {"unknown.example", "foreign.example.de", "global.example"},
            {"unknown.example", "foreign.example.de", "global.example"},
            set(),
        )
        self.assertEqual(cn_catalog, {"shared.example", "unknown.example"})
        self.assertEqual(
            profiles["cn-lean"], {"shared.example", "unknown.example"}
        )
        self.assertIn("unknown.example", profiles["cn-strict"])
        self.assertIn("foreign.example.de", profiles["global-lean"])
        self.assertNotIn("unknown.example", profiles["global-strict"])


class HealthTests(unittest.TestCase):
    def test_requires_three_confirmed_nxdomain_runs(self) -> None:
        state: dict[str, object] = {"nxdomain_streaks": {}}
        for expected in (set(), set(), {"gone.example"}):
            state, inactive = update_health_state(state, {"gone.example": "nxdomain"})
            self.assertEqual(inactive, expected)
        state, inactive = update_health_state(state, {"gone.example": "active"})
        self.assertFalse(inactive)
        self.assertEqual(state["nxdomain_streaks"], {})

    def test_unknown_breaks_consecutive_nxdomain_streak(self) -> None:
        state, inactive = update_health_state(
            {"nxdomain_streaks": {"maybe.example": 1}},
            {"maybe.example": "unknown"},
        )
        self.assertFalse(inactive)
        self.assertEqual(state["nxdomain_streaks"], {})

    def test_reward_domains_are_health_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "rules").mkdir()
            (root / "rules/version.txt").write_text("0\n", encoding="utf-8")
            (root / "rules/health-state.json").write_text(
                '{"schema":1,"confirmation_threshold":3,'
                '"nxdomain_streaks":{"reward.example":2}}\n',
                encoding="utf-8",
            )
            raw = {name: {f"{name}.example"} for name in PROFILE_NAMES}
            raw["cn-balanced"].update(raw["cn-lean"])
            raw["cn-strict"].update(raw["cn-balanced"])
            raw["global-balanced"].update(raw["global-lean"])
            raw["global-strict"].update(raw["global-balanced"])
            statuses = {domain: "active" for domains in raw.values() for domain in domains}
            statuses["reward.example"] = "nxdomain"
            manifest = materialize(
                root, raw, {"reward.example"}, statuses, dt.date(2026, 7, 23)
            )
            self.assertEqual(manifest["reward"]["rules"], 0)

    def test_profile_specific_safety_caps_accept_boundary_and_reject_overflow(self) -> None:
        self.assertEqual(PROFILE_RULE_CAPS["global-strict"], 250_000)
        self.assertGreater(PROFILE_RULE_CAPS["global-strict"], 173_840)
        profiles = {name: set() for name in PROFILE_NAMES}
        profiles["global-strict"] = {f"{index}.example" for index in range(5)}
        with patch.dict(PROFILE_RULE_CAPS, {"global-strict": 5}):
            validate_rule_caps(profiles, set())
            profiles["global-strict"].add("overflow.example")
            with self.assertRaisesRegex(ValueError, "global-strict exceeds"):
                validate_rule_caps(profiles, set())


class ActionDiagnosticsTests(unittest.TestCase):
    def test_dns_uses_bounded_workers_and_only_publish_can_write(self) -> None:
        dns_source = (ROOT / "rule_tools/dns_check.py").read_text(encoding="utf-8")
        workflow = (ROOT / ".github/workflows/rules.yml").read_text(encoding="utf-8")
        self.assertIn("queue: asyncio.Queue[str]", dns_source)
        self.assertIn('name=f"dns-worker-{index:02d}"', dns_source)
        self.assertNotIn(
            "tasks = [asyncio.create_task(guarded(domain)) for domain in domains]",
            dns_source,
        )
        self.assertLess(workflow.index("contents: read"), workflow.index("jobs:"))
        publish = workflow.index("  publish:")
        self.assertIn("contents: write", workflow[publish:])

    @unittest.skipUnless(DNSPYTHON_AVAILABLE, "dnspython is not installed")
    def test_dns_check_streams_results_and_writes_summary(self) -> None:
        from rule_tools import dns_check

        statuses = {
            "a.example": "active",
            "b.example": "exists",
            "c.example": "nxdomain",
            "d.example": "unknown",
        }

        async def fake_check(
            domain: str, resolvers: object
        ) -> tuple[str, dict[str, str], dict[str, dict[str, int]]]:
            del resolvers
            status = statuses[domain]
            return status, {"cloudflare": status}, {"cloudflare": {status: 1}}

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            input_path = root / "shard-00.domains"
            output_path = root / "shard-00.jsonl"
            summary_path = root / "shard-00.summary.json"
            input_path.write_text("d.example\nb.example\na.example\nc.example\n", encoding="utf-8")
            with patch.object(dns_check, "check_domain", new=fake_check):
                counts = dns_check.check_file(
                    input_path,
                    output_path,
                    concurrency=2,
                    summary_path=summary_path,
                    progress_seconds=3600,
                    progress_steps=2,
                )
            self.assertEqual(counts, {status: 1 for status in dns_check.STATUSES})
            rows = [json.loads(line) for line in output_path.read_text().splitlines()]
            self.assertEqual([row["domain"] for row in rows], sorted(statuses))
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertTrue(summary["complete"])
            self.assertEqual(summary["completed"], 4)
            self.assertEqual(summary["statuses"], counts)
            self.assertIn("recent_domains_per_second", summary)
            self.assertEqual(summary["resolver_outcomes"]["cloudflare"]["active"], 1)

    @unittest.skipUnless(DNSPYTHON_AVAILABLE, "dnspython is not installed")
    def test_dns_check_uses_a_bounded_worker_pool(self) -> None:
        from rule_tools import dns_check

        active = 0
        maximum = 0

        async def fake_check(
            domain: str, resolvers: object
        ) -> tuple[str, dict[str, str], dict[str, dict[str, int]]]:
            nonlocal active, maximum
            del domain, resolvers
            active += 1
            maximum = max(maximum, active)
            await asyncio.sleep(0.001)
            active -= 1
            return "active", {"cloudflare": "active"}, {
                "cloudflare": {"active": 1}
            }

        domains = [f"{index}.example" for index in range(100)]
        with patch.object(dns_check, "check_domain", new=fake_check):
            results = asyncio.run(dns_check.run_checks(domains, concurrency=4))
        self.assertEqual(len(results), len(domains))
        self.assertLessEqual(maximum, 4)
        self.assertGreater(maximum, 1)

    @unittest.skipUnless(DNSPYTHON_AVAILABLE, "dnspython is not installed")
    def test_dns_confirmation_requires_three_nxdomain_resolvers(self) -> None:
        from rule_tools import dns_check

        resolvers = {name: name for name, *_ in dns_check.RESOLVERS}
        outcomes = {
            "cloudflare": "nxdomain",
            "google": "nxdomain",
            "alidns": "nxdomain",
            "dnspod": "timeout",
        }

        async def fake_query(domain: str, resolver: object) -> str:
            del domain
            return outcomes[str(resolver)]

        with patch.object(dns_check, "query_one", new=fake_query):
            status, evidence, attempts = asyncio.run(
                dns_check.check_domain("candidate.example", resolvers)
            )
        self.assertEqual(status, "nxdomain")
        self.assertEqual(evidence["dnspod"], "timeout")
        self.assertEqual(attempts["dnspod"]["timeout"], 1)

    @unittest.skipUnless(DNSPYTHON_AVAILABLE, "dnspython is not installed")
    def test_dns_timeout_is_never_nxdomain(self) -> None:
        from rule_tools import dns_check

        resolvers = {name: name for name, *_ in dns_check.RESOLVERS}

        async def fake_query(domain: str, resolver: object) -> str:
            del domain, resolver
            return "timeout"

        with patch.object(dns_check, "query_one", new=fake_query):
            status, _evidence, attempts = asyncio.run(
                dns_check.check_domain("timeout.example", resolvers)
            )
        self.assertEqual(status, "unknown")
        for name in resolvers:
            self.assertEqual(attempts[name]["timeout"], 2)

    @unittest.skipUnless(DNSPYTHON_AVAILABLE, "dnspython is not installed")
    def test_dns_positive_fast_path_skips_confirmation_resolvers(self) -> None:
        from rule_tools import dns_check

        resolvers = {name: name for name, *_ in dns_check.RESOLVERS}
        queried: list[str] = []

        async def fake_query(domain: str, resolver: object) -> str:
            del domain
            name = str(resolver)
            queried.append(name)
            return "active" if name == "cloudflare" else "nxdomain"

        with patch.object(dns_check, "query_one", new=fake_query):
            status, evidence, _attempts = asyncio.run(
                dns_check.check_domain("live.example", resolvers)
            )
        self.assertEqual(status, "active")
        self.assertIn("cloudflare", evidence)
        self.assertTrue(set(evidence) <= set(dns_check.PRIMARY_RESOLVERS))
        self.assertNotIn("alidns", queried)

    def test_rejected_source_keeps_normalized_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "rules").mkdir()
            (root / "rules/sources.json").write_text(
                json.dumps(
                    {
                        "sources": [
                            {
                                "id": "sample",
                                "name": "Sample",
                                "type": "remote",
                                "url": "https://example.invalid/list",
                                "license": "test",
                                "min_domains": 3,
                                "max_domains": 10,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            with patch("rule_tools.fetch_source.fetch", return_value="a.example\nb.example\n"):
                with self.assertRaisesRegex(RuntimeError, "kept for diagnostics"):
                    fetch_one(root, "sample")
            self.assertEqual(
                load_domains(root / "staging/sources/sample.domains"),
                {"a.example", "b.example"},
            )
            metadata = json.loads(
                (root / "staging/source-meta/sample.json").read_text(encoding="utf-8")
            )
            self.assertFalse(metadata["within_expected_range"])


class RepositoryDataTests(unittest.TestCase):
    def test_owned_snapshot_and_reward_counts(self) -> None:
        weig = load_domains(ROOT / "rules/sources/owned/weig-base-20260723.domains")
        reward = load_domains(ROOT / "rules/reward/reward-ads.domains")
        self.assertEqual(len(weig), 17_115)
        self.assertEqual(len(reward), 74)
        self.assertEqual(len(weig - reward), 17_041)

    def test_source_configuration_has_only_selected_upstreams(self) -> None:
        config = json.loads((ROOT / "rules/sources.json").read_text(encoding="utf-8"))
        ids = {source["id"] for source in config["sources"]}
        self.assertEqual(
            ids, {"weig-base", "anti-ad", "217heidai-lite", "hagezi-light", "stevenblack"}
        )


class ReleaseTests(unittest.TestCase):
    def test_prepare_builds_six_profiles_and_stable_shards(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "rules/sources/owned").mkdir(parents=True)
            (root / "rules/reward").mkdir(parents=True)
            (root / "staging/sources").mkdir(parents=True)
            files = {
                root / "rules/sources/owned/weig-base-20260723.domains": "base.cn\n",
                root / "rules/reward/reward-ads.domains": "reward.example\n",
                root / "staging/sources/anti-ad.domains": "anti.cn\n",
                root / "staging/sources/217heidai-lite.domains": "strict.cn\n",
                root / "staging/sources/hagezi-light.domains": "both.global\nhagezi.global\n",
                root / "staging/sources/stevenblack.domains": "both.global\nsteven.global\n",
            }
            for path, content in files.items():
                path.write_text(content, encoding="utf-8")
            summary = prepare(root, 4)
            self.assertEqual(summary["shards"], 4)
            self.assertEqual(summary["candidates"], 7)
            self.assertEqual(len(list((root / "staging/shards").glob("*.domains"))), 4)
            cn_strict = load_domains(root / "staging/profiles/cn-strict.domains")
            global_lean = load_domains(root / "staging/profiles/global-lean.domains")
            self.assertEqual(cn_strict, {"base.cn", "anti.cn", "strict.cn"})
            self.assertEqual(global_lean, {"both.global"})

    def test_materialized_release_is_reproducible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "rules").mkdir()
            (root / "rules/version.txt").write_text("2026072201\n", encoding="utf-8")
            (root / "rules/health-state.json").write_text(
                '{"schema":1,"confirmation_threshold":3,"nxdomain_streaks":{}}\n',
                encoding="utf-8",
            )
            raw = {name: {f"{name}.example"} for name in PROFILE_NAMES}
            raw["cn-balanced"].update(raw["cn-lean"])
            raw["cn-strict"].update(raw["cn-balanced"])
            raw["global-balanced"].update(raw["global-lean"])
            raw["global-strict"].update(raw["global-balanced"])
            reward = {"reward.qq.example", "reward.video.example"}
            statuses = {domain: "active" for domains in raw.values() for domain in domains}
            manifest = materialize(root, raw, reward, statuses, dt.date(2026, 7, 23))
            self.assertEqual(manifest["defaults"]["cn_profile"], "lean")
            self.assertEqual(manifest["defaults"]["global_profile"], "off")
            first = root / "dist/first.zip"
            second = root / "dist/second.zip"
            build(root, first)
            build(root, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(set(archive.namelist()), set(release_files()))


if __name__ == "__main__":
    unittest.main()
