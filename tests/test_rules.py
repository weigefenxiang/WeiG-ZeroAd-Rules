from __future__ import annotations

import datetime as dt
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from rule_tools.build_release import build, release_files
from rule_tools.common import domains_from_line, load_domains, normalize_domain
from rule_tools.pipeline import (
    PROFILE_NAMES,
    apply_inactive,
    compute_raw_profiles,
    materialize,
    update_health_state,
)
from rule_tools.prepare import prepare


ROOT = Path(__file__).resolve().parents[1]


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
        self.profiles, self.cn_catalog = compute_raw_profiles(
            self.weig, self.anti, self.ad217, self.hagezi, self.steven, self.reward
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
