import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

GRADIO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(GRADIO_ROOT))

from demo_logic import (  # noqa: E402
    load_allocation_fixture,
    load_evidence_fixture,
    render_allocation,
    scenario_by_id,
    validate_live_402,
)


VALID_402 = {
    "x402Version": 1,
    "accepts": [
        {
            "scheme": "exact",
            "network": "base-sepolia",
            "maxAmountRequired": "250000",
            "resource": "https://neverhandedover.com/api/invoke/optimizing-claude-code-prompts",
            "payTo": "0x25005dfac23d4bc45c801eaeb6c8b5a2bab0f189",
            "asset": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
        }
    ],
}


def offer_with_amount(amount):
    body = json.loads(json.dumps(VALID_402))
    body["accepts"][0]["maxAmountRequired"] = amount
    return body


class Live402ValidationTests(unittest.TestCase):
    def test_accepts_only_the_fixed_valid_402_offer(self):
        result = validate_live_402(402, VALID_402)
        self.assertTrue(result["live"])
        self.assertEqual(result["status"], 402)
        self.assertEqual(result["offer"]["maxAmountRequired"], "250000")

    def test_rejects_non_402_and_malformed_offers(self):
        cases = [
            (200, VALID_402),
            (500, VALID_402),
            (402, {**VALID_402, "x402Version": 2}),
            (402, {**VALID_402, "accepts": []}),
        ]
        for field, value in [
            ("scheme", "upto"),
            ("network", "base"),
            ("maxAmountRequired", "0.25"),
            ("maxAmountRequired", "01"),
            ("resource", "https://attacker.example/invoke"),
            ("payTo", ""),
            ("asset", ""),
        ]:
            body = json.loads(json.dumps(VALID_402))
            body["accepts"][0][field] = value
            cases.append((402, body))
        for status, body in cases:
            with self.subTest(status=status, body=body):
                result = validate_live_402(status, body)
                self.assertFalse(result["live"])
                self.assertIn("valid 402", result["error"])

    def test_rejects_five_thousand_digit_amount_without_raising(self):
        result = validate_live_402(402, offer_with_amount("9" * 5_000))
        self.assertEqual(
            result,
            {
                "live": False,
                "status": 402,
                "offer": None,
                "error": "live endpoint did not return a valid 402 offer",
            },
        )

    def test_enforces_uint256_atomic_amount_boundary(self):
        maximum = str((1 << 256) - 1)
        self.assertTrue(validate_live_402(402, offer_with_amount(maximum))["live"])
        self.assertFalse(validate_live_402(402, offer_with_amount(str(1 << 256)))["live"])


class FixtureTests(unittest.TestCase):
    def test_default_and_mode_statuses_are_fixture_controlled(self):
        fixture = load_allocation_fixture()
        self.assertEqual(fixture["defaultScenarioId"], "intra-org")
        self.assertEqual(scenario_by_id(fixture)["id"], "intra-org")
        self.assertEqual(scenario_by_id(fixture, "education")["status"], "deferred")
        self.assertEqual(
            scenario_by_id(fixture, "marketplace")["status"],
            "phase_3_optionality",
        )

    def test_rendered_rows_are_kernel_journal_rows_and_conserve_gross(self):
        fixture = load_allocation_fixture()
        for scenario in fixture["scenarios"]:
            model = render_allocation(fixture, scenario["id"])
            self.assertEqual(model["implementationNote"], scenario["implementationNote"])
            expected_entries = scenario["allocation"]["journalEntries"]
            self.assertEqual(len(model["rows"]), len(expected_entries))
            for row, entry in zip(model["rows"], expected_entries, strict=True):
                self.assertEqual(row["category"], entry["category"])
                self.assertEqual(row["debitAccountId"], entry["debitAccountId"])
                self.assertEqual(row["creditAccountId"], entry["creditAccountId"])
                self.assertEqual(row["amountAtomic"], entry["amountAtomic"])
            total = sum(int(entry["amountAtomic"]) for entry in expected_entries)
            self.assertEqual(total, int(scenario["grossAtomic"]))
            self.assertIn(
                scenario["allocationKind"],
                ("internal_invocation_award", "external_royalty_claim"),
            )

    def test_evidence_suppresses_unreproducible_percentiles(self):
        evidence = load_evidence_fixture()
        rendered = json.dumps(evidence).lower()
        for percentile in ("p" + str(50), "p" + str(95)):
            self.assertNotIn(percentile, rendered)
        self.assertFalse(evidence["historicalOverhead"]["publicationAllowed"])
        self.assertEqual(len(evidence["historicalSkillLegTransactions"]), 1)

    def test_root_is_standalone_and_integrity_drift_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            copied_root = Path(temporary) / "copied-gradio"
            shutil.copytree(GRADIO_ROOT, copied_root)
            module_path = copied_root / "demo_logic.py"
            spec = importlib.util.spec_from_file_location("copied_demo_logic", module_path)
            module = importlib.util.module_from_spec(spec)
            original_cwd = os.getcwd()
            try:
                os.chdir(tempfile.gettempdir())
                spec.loader.exec_module(module)
                copied_fixture = module.load_allocation_fixture()
            finally:
                os.chdir(original_cwd)
            self.assertEqual(copied_fixture["defaultScenarioId"], "intra-org")
            self.assertNotIn("shared", str(module.DATA_DIRECTORY))

            evidence_path = copied_root / "data" / "evidence.json"
            original = evidence_path.read_bytes()
            evidence_path.write_bytes(original + b" ")
            with self.assertRaisesRegex(
                ValueError,
                "packaged fixture integrity mismatch: evidence.json",
            ):
                module.load_evidence_fixture()

    def test_integrity_manifest_matches_current_raw_bytes(self):
        data = GRADIO_ROOT / "data"
        manifest = json.loads((data / "fixture-integrity.json").read_text())
        for name, expected in manifest["files"].items():
            raw = (data / name).read_bytes()
            self.assertEqual(expected["bytes"], len(raw))
            self.assertEqual(expected["sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())

    def test_readme_marks_internal_award_model_proposed_and_noncanonical(self):
        readme = (GRADIO_ROOT / "README.md").read_text()
        self.assertIn("PROPOSED / NONCANONICAL", readme)
        self.assertRegex(readme, r"(?i)employer-funded internal Invocation-award.*pending explicit approval")


if __name__ == "__main__":
    unittest.main()
