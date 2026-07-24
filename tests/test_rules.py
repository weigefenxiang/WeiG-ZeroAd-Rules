from __future__ import annotations

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
    PROFILE_NAMES,
    apply_inactive,
    compute_raw_profiles,
    materialize,
    update_health_state,
)
from rule_tools.prepare import prepare
from rule_tools.region import classify_regions


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
        self.weig = {"base.cn", "shared.cn", "reward.cn"}
        self.anti = {"shared.cn", "anti.cn", "cross.example", "reward.cn"}
        self.ad217 = {"strict.cn", "cross.example", "global-overlap.example"}
        self.hagezi = {"global-overlap.example", "cross.example", "hagezi.global", "both.global"}
        self.steven = {"steven.global", "both.global", "reward.global"}
        self.confirmed_cn = self.weig | self.anti | self.ad217
        self.profiles, self.cn_catalog = compute_raw_profiles(
            self.weig,
            self.anti,
            self.ad217,
            self.hagezi,
            self.steven,
            self.reward,
            self.confirmed_cn,
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
        self.assertEqual(self.profiles["cn-lean"], {"base.cn", "shared.cn"})
        self.assertIn("anti.cn", self.profiles["cn-balanced"])
        self.assertIn("strict.cn", self.profiles["cn-strict"])
        self.assertEqual(self.profiles["global-lean"], {"both.global"})
        self.assertIn("hagezi.global", self.profiles["global-balanced"])
        self.assertIn("steven.global", self.profiles["global-strict"])

    def test_inactive_is_removed_from_every_profile(self) -> None:
        filtered = apply_inactive(self.profiles, {"base.cn", "both.global"})
        self.assertNotIn("base.cn", filtered["cn-lean"])
        self.assertNotIn("both.global", filtered["global-strict"])

    def test_only_confirmed_cn_is_kept_in_domestic_profiles(self) -> None:
        profiles, cn_catalog = compute_raw_profiles(
            {"base.cn", "unknown.example", "foreign.example.de"},
            {"anti.cn", "foreign.example.de"},
            {"strict.cn"},
            {"unknown.example", "foreign.example.de", "global.example"},
            {"unknown.example", "foreign.example.de", "global.example"},
            set(),
            {"base.cn", "anti.cn", "strict.cn"},
        )
        self.assertNotIn("foreign.example.de", cn_catalog)
        self.assertNotIn("unknown.example", cn_catalog)
        self.assertNotIn("foreign.example.de", profiles["cn-strict"])
        self.assertNotIn("unknown.example", profiles["cn-strict"])
        self.assertIn("foreign.example.de", profiles["global-lean"])
        self.assertIn("unknown.example", profiles["global-lean"])


class RegionTests(unittest.TestCase):
    def test_region_classifier_uses_cn_platforms_foreign_tlds_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            domains = {"sdk.qq.com", "ads.example.de", "unclassified.example"}
            regions = classify_regions(root, domains)
            self.assertEqual(regions.cn_confirmed, {"sdk.qq.com"})
            self.assertEqual(regions.global_confirmed, {"ads.example.de"})
            self.assertEqual(regions.unknown, {"unclassified.example"})

    def test_manual_override_has_priority_over_suffix_heuristic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            region = root / "rules/region"
            region.mkdir(parents=True)
            (region / "cn-overrides.domains").write_text(
                "service.example.de\n", encoding="utf-8"
            )
            regions = classify_regions(root, {"service.example.de"})
            self.assertEqual(regions.cn_confirmed, {"service.example.de"})
            self.assertFalse(regions.global_confirmed)


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


class ActionDiagnosticsTests(unittest.TestCase):
    @unittest.skipUnless(DNSPYTHON_AVAILABLE, "dnspython is not installed")
    def test_dns_check_streams_results_and_writes_summary(self) -> None:
        from rule_tools import dns_check

        statuses = {
            "a.example": "active",
            "b.example": "exists",
            "c.example": "nxdomain",
            "d.example": "unknown",
        }

        async def fake_check(domain: str, resolvers: object) -> tuple[str, dict[str, str]]:
            del resolvers
            status = statuses[domain]
            return status, {"test": status}

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
