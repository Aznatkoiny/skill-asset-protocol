"""Fixture-only accounting and strict live-402 validation for the Gradio Space."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

DATA_DIRECTORY = Path(__file__).resolve().parent / "data"
LIVE_ENDPOINT = "https://neverhandedover.com/api/invoke/optimizing-claude-code-prompts"
EXPECTED_PAY_TO = "0x25005dfac23d4bc45c801eaeb6c8b5a2bab0f189"
EXPECTED_ASSET = "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
_ATOMIC_PATTERN = re.compile(r"^(0|[1-9][0-9]*)$")
_ADDRESS_PATTERN = re.compile(r"^0x[0-9a-fA-F]{40}$")
_SHA_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_FIXTURE_NAMES = {"evidence.json", "public-demo-allocation.json"}


def _integrity_error(file_name: str) -> ValueError:
    return ValueError(f"packaged fixture integrity mismatch: {file_name}")


def _load_integrity_manifest() -> dict[str, Any]:
    try:
        raw = (DATA_DIRECTORY / "fixture-integrity.json").read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as error:
        raise _integrity_error("fixture-integrity.json") from error
    if not isinstance(value, dict) or set(value) != {"schemaVersion", "generatedBy", "files"}:
        raise _integrity_error("fixture-integrity.json")
    if value["schemaVersion"] != 1 or value["generatedBy"] != "hf-space/scripts/package-space-fixtures.mjs":
        raise _integrity_error("fixture-integrity.json")
    files = value["files"]
    if not isinstance(files, dict) or set(files) != _FIXTURE_NAMES:
        raise _integrity_error("fixture-integrity.json")
    for file_name, metadata in files.items():
        if not isinstance(metadata, dict) or set(metadata) != {"sha256", "bytes"}:
            raise _integrity_error("fixture-integrity.json")
        if (
            not isinstance(metadata["bytes"], int)
            or isinstance(metadata["bytes"], bool)
            or metadata["bytes"] <= 0
            or not isinstance(metadata["sha256"], str)
            or not _SHA_PATTERN.fullmatch(metadata["sha256"])
        ):
            raise _integrity_error("fixture-integrity.json")
    return value


def _load_verified_json(file_name: str) -> dict[str, Any]:
    if file_name not in _FIXTURE_NAMES:
        raise ValueError("unsupported packaged fixture")
    manifest = _load_integrity_manifest()
    try:
        raw = (DATA_DIRECTORY / file_name).read_bytes()
    except OSError as error:
        raise _integrity_error(file_name) from error
    expected = manifest["files"][file_name]
    actual_hash = "sha256:" + hashlib.sha256(raw).hexdigest()
    if len(raw) != expected["bytes"] or actual_hash != expected["sha256"]:
        raise _integrity_error(file_name)
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"invalid packaged fixture JSON: {file_name}") from error
    if not isinstance(value, dict):
        raise ValueError(f"invalid packaged fixture shape: {file_name}")
    return value


def load_allocation_fixture() -> dict[str, Any]:
    fixture = _load_verified_json("public-demo-allocation.json")
    if (
        fixture.get("schemaVersion") != 1
        or fixture.get("evidenceStatus") != "synthetic_accounting_illustration"
        or fixture.get("defaultScenarioId") != "intra-org"
        or not isinstance(fixture.get("scenarios"), list)
        or len(fixture["scenarios"]) != 3
    ):
        raise ValueError("invalid public demo accounting fixture")
    expected_modes = {
        "intra-org": ("internal_invocation_award", "terminal_product_spike"),
        "education": ("external_royalty_claim", "deferred"),
        "marketplace": ("external_royalty_claim", "phase_3_optionality"),
    }
    seen = set()
    for scenario in fixture["scenarios"]:
        if not isinstance(scenario, dict) or scenario.get("id") not in expected_modes:
            raise ValueError("invalid public demo scenario")
        scenario_id = scenario["id"]
        if scenario_id in seen:
            raise ValueError("duplicate public demo scenario")
        seen.add(scenario_id)
        expected_kind, expected_status = expected_modes[scenario_id]
        if scenario.get("allocationKind") != expected_kind or scenario.get("status") != expected_status:
            raise ValueError("invalid public demo scenario status")
    if seen != set(expected_modes):
        raise ValueError("missing public demo scenario")
    return fixture


def load_evidence_fixture() -> dict[str, Any]:
    evidence = _load_verified_json("evidence.json")
    overhead = evidence.get("historicalOverhead")
    transactions = evidence.get("historicalSkillLegTransactions")
    if (
        evidence.get("schemaVersion") != 1
        or not isinstance(overhead, dict)
        or overhead.get("evidenceStatus") != "historical_unreproducible"
        or overhead.get("publicationAllowed") is not False
        or not isinstance(transactions, list)
        or len(transactions) != 1
        or not isinstance(transactions[0], dict)
        or transactions[0].get("evidenceStatus") != "historical_transaction_receipt_verified"
    ):
        raise ValueError("invalid public demo evidence fixture")
    return evidence


def _invalid_402(status: Any) -> dict[str, Any]:
    return {
        "live": False,
        "status": status if isinstance(status, int) and not isinstance(status, bool) else None,
        "offer": None,
        "error": "live endpoint did not return a valid 402 offer",
    }


def validate_live_402(status: Any, body: Any) -> dict[str, Any]:
    """Return a bounded view only when the fixed endpoint returns a valid x402 v1 offer."""
    if status != 402 or isinstance(status, bool) or not isinstance(body, dict):
        return _invalid_402(status)
    accepts = body.get("accepts")
    if body.get("x402Version") != 1 or not isinstance(accepts, list) or not accepts:
        return _invalid_402(status)
    offer = accepts[0]
    if not isinstance(offer, dict):
        return _invalid_402(status)
    amount = offer.get("maxAmountRequired")
    pay_to = offer.get("payTo")
    asset = offer.get("asset")
    if (
        offer.get("scheme") != "exact"
        or offer.get("network") != "base-sepolia"
        or not isinstance(amount, str)
        or not _ATOMIC_PATTERN.fullmatch(amount)
        or int(amount) <= 0
        or offer.get("resource") != LIVE_ENDPOINT
        or not isinstance(pay_to, str)
        or not _ADDRESS_PATTERN.fullmatch(pay_to)
        or pay_to.lower() != EXPECTED_PAY_TO
        or not isinstance(asset, str)
        or not _ADDRESS_PATTERN.fullmatch(asset)
        or asset.lower() != EXPECTED_ASSET
    ):
        return _invalid_402(status)
    return {
        "live": True,
        "status": 402,
        "offer": {
            "scheme": "exact",
            "network": "base-sepolia",
            "maxAmountRequired": amount,
            "resource": LIVE_ENDPOINT,
            "payTo": pay_to,
            "asset": asset,
        },
        "error": None,
    }


def scenario_by_id(fixture: dict[str, Any], scenario_id: str | None = None) -> dict[str, Any]:
    selected = scenario_id if scenario_id is not None else fixture.get("defaultScenarioId")
    if not isinstance(selected, str):
        raise ValueError("scenario identifier must be a string")
    for scenario in fixture.get("scenarios", []):
        if isinstance(scenario, dict) and scenario.get("id") == selected:
            return scenario
    raise ValueError(f"unknown public demo scenario: {selected}")


def _parse_atomic(value: Any, label: str) -> int:
    if not isinstance(value, str) or not _ATOMIC_PATTERN.fullmatch(value):
        raise ValueError(f"invalid atomic amount: {label}")
    return int(value)


def render_allocation(fixture: dict[str, Any], scenario_id: str | None = None) -> dict[str, Any]:
    scenario = scenario_by_id(fixture, scenario_id)
    allocation = scenario.get("allocation")
    entries = allocation.get("journalEntries") if isinstance(allocation, dict) else None
    display_amounts = scenario.get("journalEntryDisplayUsdc")
    expected_debit = scenario.get("expectedGrossDebitAccountId")
    if (
        not isinstance(entries, list)
        or not entries
        or not isinstance(display_amounts, list)
        or len(display_amounts) != len(entries)
        or not isinstance(expected_debit, str)
        or not expected_debit
    ):
        raise ValueError("invalid kernel journal fixture")
    rows = []
    total = 0
    expected_entry_keys = {"category", "debitAccountId", "creditAccountId", "amountAtomic"}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or set(entry) != expected_entry_keys:
            raise ValueError("invalid kernel journal entry")
        if (
            entry.get("debitAccountId") != expected_debit
            or not isinstance(entry.get("creditAccountId"), str)
            or not entry["creditAccountId"]
            or not isinstance(entry.get("category"), str)
            or not entry["category"]
            or not isinstance(display_amounts[index], str)
        ):
            raise ValueError("invalid kernel journal account")
        total += _parse_atomic(entry.get("amountAtomic"), f"journalEntries[{index}]")
        rows.append(
            {
                "category": entry["category"],
                "debitAccountId": entry["debitAccountId"],
                "creditAccountId": entry["creditAccountId"],
                "amountAtomic": entry["amountAtomic"],
                "amountUsdc": display_amounts[index],
            }
        )
    gross = _parse_atomic(scenario.get("grossAtomic"), "grossAtomic")
    if total != gross:
        raise ValueError("kernel journal does not conserve gross")
    return {
        "scenarioId": scenario["id"],
        "label": scenario["label"],
        "status": scenario["status"],
        "policy": scenario["policy"],
        "allocationKind": scenario["allocationKind"],
        "accountingLabel": scenario["accountingLabel"],
        "implementationNote": scenario["implementationNote"],
        "settlementNote": scenario["settlementNote"],
        "grossAtomic": scenario["grossAtomic"],
        "grossUsdc": scenario["grossUsdc"],
        "rows": rows,
    }
