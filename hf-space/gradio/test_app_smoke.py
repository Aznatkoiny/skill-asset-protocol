import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import gradio as gr
import httpx

GRADIO_ROOT = Path(__file__).resolve().parent

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


class FakeResponse:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body


def import_app():
    sys.path.insert(0, str(GRADIO_ROOT))
    sys.modules.pop("demo_logic", None)
    spec = importlib.util.spec_from_file_location("plan10_gradio_app", GRADIO_ROOT / "app.py")
    module = importlib.util.module_from_spec(spec)
    with patch.object(httpx, "post", side_effect=AssertionError("network during import")), patch.object(
        gr.Blocks,
        "launch",
        side_effect=AssertionError("server launch during import"),
    ):
        spec.loader.exec_module(module)
    return module


class AppSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = import_app()

    def test_import_builds_blocks_without_network_or_launch(self):
        self.assertIsInstance(self.app.demo, gr.Blocks)
        config = self.app.demo.get_config_file()
        self.assertTrue(
            any(component.get("props", {}).get("value") == "intra-org" for component in config["components"])
        )
        self.assertTrue(
            any(dependency.get("api_name") == "check_live_402" for dependency in config["dependencies"])
        )

    def test_actual_wired_handler_distinguishes_live_non_402_and_failure(self):
        with patch.object(httpx, "post", return_value=FakeResponse(402, VALID_402)) as request:
            result = self.app.check_live_402()
        self.assertTrue(result["live"])
        self.assertEqual(result["source"], "live_http_response")
        self.assertFalse(request.call_args.kwargs["follow_redirects"])
        self.assertIsInstance(request.call_args.kwargs["timeout"], httpx.Timeout)

        with patch.object(httpx, "post", return_value=FakeResponse(200, {"ok": True})):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["status"], 200)

        with patch.object(httpx, "post", side_effect=httpx.ConnectError("offline")):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["source"], "live_request_failed_no_cache")
        self.assertNotIn("offline", json_safe(result))


def json_safe(value):
    return str(value).lower()


if __name__ == "__main__":
    unittest.main()
