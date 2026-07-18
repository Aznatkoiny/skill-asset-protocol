"""Skill Asset Protocol public demo, backed only by packaged verified fixtures."""

from __future__ import annotations

import httpx
import gradio as gr

from demo_logic import (
    LIVE_ENDPOINT,
    load_allocation_fixture,
    load_evidence_fixture,
    render_allocation,
    validate_live_402,
)

REQUEST_BODY = {"input": "help me tighten this prompt"}
REQUEST_TIMEOUT = httpx.Timeout(5.0, connect=3.0)


def check_live_402():
    """Read the fixed endpoint once; never follow redirects or use a cached offer."""
    try:
        response = httpx.post(
            LIVE_ENDPOINT,
            json=REQUEST_BODY,
            headers={"accept": "application/json"},
            timeout=REQUEST_TIMEOUT,
            follow_redirects=False,
        )
        body = response.json()
    except (httpx.HTTPError, ValueError, TypeError):
        return {
            "live": False,
            "status": None,
            "offer": None,
            "error": "live endpoint request failed; no cached response is represented as live",
            "source": "live_request_failed_no_cache",
        }
    result = validate_live_402(response.status_code, body)
    return {**result, "source": "live_http_response"}


def allocation_markdown(scenario_id):
    model = render_allocation(ALLOCATION_FIXTURE, scenario_id)
    rows = [
        "| category | debit account | credit account | atomic units | testnet USDC |",
        "|---|---|---|---:|---:|",
    ]
    for row in model["rows"]:
        rows.append(
            f"| `{row['category']}` | `{row['debitAccountId']}` | "
            f"`{row['creditAccountId']}` | `{row['amountAtomic']}` | `{row['amountUsdc']}` |"
        )
    return "\n".join(
        [
            f"### {model['label']}",
            f"**Status:** `{model['status']}` · **Policy:** `{model['policy']}`",
            "",
            model["accountingLabel"],
            "",
            model["implementationNote"],
            "",
            f"Gross: `{model['grossAtomic']}` atomic units (`{model['grossUsdc']}` testnet USDC)",
            "",
            *rows,
            "",
            model["settlementNote"],
        ]
    )


def evidence_markdown(evidence):
    overhead = evidence["historicalOverhead"]
    transaction = evidence["historicalSkillLegTransactions"][0]
    boundaries = "\n".join(f"- Does not prove: {item}" for item in transaction["doesNotProve"])
    return "\n".join(
        [
            "## Evidence status",
            "",
            f"**Suppressed historical route evidence:** `{overhead['evidenceStatus']}`; publication allowed: `{str(overhead['publicationAllowed']).lower()}`.",
            "",
            overhead["publicText"],
            "",
            f"**Narrow historical transaction evidence:** {transaction['label']}.",
            "",
            f"Manifest record: `{transaction['manifestPath']}`",
            "",
            boundaries,
        ]
    )


def build_demo():
    choices = [(scenario["label"], scenario["id"]) for scenario in ALLOCATION_FIXTURE["scenarios"]]
    with gr.Blocks(title="Skill Asset Protocol — verified accounting demo") as blocks:
        gr.Markdown(
            "# Skill Asset Protocol\n\n"
            "A testnet-only accounting and HTTP 402 research demo. No real funds, "
            "wallet signing, payment, withdrawal, deployment, or publication occurs here."
        )
        with gr.Tab("Accounting illustration"):
            scenario = gr.Dropdown(
                choices=choices,
                value=ALLOCATION_FIXTURE["defaultScenarioId"],
                label="Distribution mode",
            )
            allocation = gr.Markdown(value=allocation_markdown(ALLOCATION_FIXTURE["defaultScenarioId"]))
            scenario.change(
                allocation_markdown,
                inputs=scenario,
                outputs=allocation,
                api_name=False,
            )
        with gr.Tab("Live HTTP 402 check"):
            gr.Markdown(
                "This performs one unpaid POST to the fixed Collar endpoint. Redirects are refused, "
                "the timeout is bounded, and only a strict x402 v1 Base Sepolia offer is marked live."
            )
            live_button = gr.Button("Check fixed live endpoint")
            live_result = gr.JSON(label="Validated live response")
            live_button.click(
                check_live_402,
                outputs=live_result,
                api_name="check_live_402",
            )
        with gr.Tab("Evidence boundaries"):
            gr.Markdown(evidence_markdown(EVIDENCE_FIXTURE))
    return blocks


ALLOCATION_FIXTURE = load_allocation_fixture()
EVIDENCE_FIXTURE = load_evidence_fixture()
demo = build_demo()


if __name__ == "__main__":
    demo.launch()
