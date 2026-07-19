import importlib.util
import json
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
    def __init__(self, status_code, body=None, *, chunks=None, content_length=None, before_chunk=None):
        self.status_code = status_code
        encoded = json.dumps(body, separators=(",", ":")).encode() if chunks is None else None
        self._chunks = list(chunks) if chunks is not None else [encoded]
        self.headers = {
            "content-length": str(len(encoded)) if content_length is None and encoded is not None
            else content_length
        }
        self.before_chunk = before_chunk
        self.iteration_count = 0

    def iter_bytes(self, chunk_size=None):
        for chunk in self._chunks:
            if self.before_chunk is not None:
                self.before_chunk(self.iteration_count)
            self.iteration_count += 1
            yield chunk


class FakeStream:
    def __init__(self, response):
        self.response = response

    def __enter__(self):
        return self.response

    def __exit__(self, exc_type, exc_value, traceback):
        return False


def import_app():
    sys.path.insert(0, str(GRADIO_ROOT))
    sys.modules.pop("demo_logic", None)
    spec = importlib.util.spec_from_file_location("plan10_gradio_app", GRADIO_ROOT / "app.py")
    module = importlib.util.module_from_spec(spec)
    with patch.object(httpx, "post", side_effect=AssertionError("network during import")), patch.object(
        httpx,
        "stream",
        side_effect=AssertionError("network during import"),
    ), patch.object(
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

    def setUp(self):
        for method_name in ("post", "stream"):
            network = patch.object(
                httpx,
                method_name,
                side_effect=AssertionError(f"unstubbed HTTP request through {method_name}"),
            )
            network.start()
            self.addCleanup(network.stop)

    def test_import_builds_blocks_without_network_or_launch(self):
        self.assertIsInstance(self.app.demo, gr.Blocks)
        config = self.app.demo.get_config_file()
        self.assertTrue(
            any(component.get("props", {}).get("value") == "intra-org" for component in config["components"])
        )
        self.assertTrue(
            any("PROPOSED / NONCANONICAL" in component.get("props", {}).get("value", "")
                for component in config["components"])
        )
        live_function_id, live_function = next(
            (function_id, fn)
            for function_id, fn in self.app.demo.fns.items()
            if fn.name == "check_live_402"
        )
        live_dependency = next(
            dependency for dependency in config["dependencies"]
            if dependency.get("id") == live_function_id
        )
        self.assertEqual(live_dependency["api_visibility"], "private")
        self.assertNotEqual(live_dependency["api_name"], "check_live_402")
        self.assertTrue(live_dependency["queue"])
        self.assertEqual(live_function.concurrency_limit, 1)
        self.assertEqual(live_function.concurrency_id, "fixed-live-402-check")
        self.assertFalse(self.app.demo.api_open)
        self.assertEqual(self.app.demo._queue.max_size, 1)

    def test_actual_wired_handler_distinguishes_live_non_402_and_failure(self):
        with patch.object(httpx, "stream", return_value=FakeStream(FakeResponse(402, VALID_402))) as request:
            result = self.app.check_live_402()
        self.assertTrue(result["live"])
        self.assertEqual(result["source"], "live_http_response")
        self.assertEqual(request.call_args.args, ("POST", self.app.LIVE_ENDPOINT))
        self.assertFalse(request.call_args.kwargs["follow_redirects"])
        self.assertIsInstance(request.call_args.kwargs["timeout"], httpx.Timeout)

        with patch.object(httpx, "stream", return_value=FakeStream(FakeResponse(200, {"ok": True}))):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["status"], 200)

        with patch.object(httpx, "stream", side_effect=httpx.ConnectError("offline")):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["source"], "live_request_failed_no_cache")
        self.assertNotIn("offline", json_safe(result))

    def test_actual_wired_handler_returns_non_live_for_five_thousand_digit_amount(self):
        invalid = {
            **VALID_402,
            "accepts": [{**VALID_402["accepts"][0], "maxAmountRequired": "9" * 5_000}],
        }
        with patch.object(httpx, "stream", return_value=FakeStream(FakeResponse(402, invalid))):
            result = self.app.check_live_402()
        self.assertEqual(
            result,
            {
                "live": False,
                "status": 402,
                "offer": None,
                "error": "live endpoint did not return a valid 402 offer",
                "source": "live_http_response",
            },
        )

    def test_actual_wired_handler_contains_validation_exceptions(self):
        with patch.object(httpx, "stream", return_value=FakeStream(FakeResponse(402, VALID_402))), patch.object(
            self.app,
            "validate_live_402",
            side_effect=ValueError("invalid response boundary"),
        ):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["source"], "live_request_failed_no_cache")
        self.assertNotIn("invalid response boundary", json_safe(result))

    def test_actual_wired_handler_prechecks_length_and_caps_chunked_bodies(self):
        declared_oversize = FakeResponse(
            402,
            VALID_402,
            content_length=str(self.app.MAX_LIVE_RESPONSE_BYTES + 1),
        )
        with patch.object(httpx, "stream", return_value=FakeStream(declared_oversize)):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["source"], "live_request_failed_no_cache")
        self.assertEqual(declared_oversize.iteration_count, 0)

        chunked_oversize = FakeResponse(
            402,
            chunks=[b"x" * self.app.MAX_LIVE_RESPONSE_BYTES, b"x"],
            content_length="",
        )
        with patch.object(httpx, "stream", return_value=FakeStream(chunked_oversize)):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["source"], "live_request_failed_no_cache")
        self.assertEqual(chunked_oversize.iteration_count, 2)

    def test_actual_wired_handler_contains_malformed_and_deadline_failures(self):
        malformed = FakeResponse(402, chunks=[b"{"], content_length="")
        with patch.object(httpx, "stream", return_value=FakeStream(malformed)):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["source"], "live_request_failed_no_cache")

        now = [0.0]
        slow = FakeResponse(
            402,
            VALID_402,
            content_length="",
            before_chunk=lambda _index: now.__setitem__(0, self.app.LIVE_RESPONSE_DEADLINE_SECONDS + 1),
        )
        with patch.object(httpx, "stream", return_value=FakeStream(slow)), patch.object(
            self.app.time,
            "monotonic",
            side_effect=lambda: now[0],
        ):
            result = self.app.check_live_402()
        self.assertFalse(result["live"])
        self.assertEqual(result["source"], "live_request_failed_no_cache")


def json_safe(value):
    return str(value).lower()


if __name__ == "__main__":
    unittest.main()
