import json
import os
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4
from types import SimpleNamespace

from fastapi import FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError
from starlette.requests import Request

from api.auth import ApiClient, load_api_clients, require_api_client
from api.config import ApiSettings
from api.main import BodyLimitMiddleware, score_window
from api.schemas import EventFeatures, ScoreRequest
from api.scoring import score_features


SECRET = "test-api-secret-0123456789-abcdefghijk"
FEATURES = {
    "destination_port": 22,
    "protocol": "SSH",
    "packets_per_second": 35.0,
    "failed_login_count": 8,
    "request_count": 8,
    "payload_length": 80.0,
    "connection_duration": 0.6,
    "unusual_port": 0.0,
    "login_frequency": 2.0,
    "special_char_ratio": 0.04,
    "distinct_ports": 1,
}


class ScoringApiTests(unittest.TestCase):
    def test_api_settings_require_a_postgresql_driver_and_secret_file(self):
        with patch.dict(os.environ, {"DATABASE_URL": "sqlite:///local.db",
                                     "ARES_API_KEYS_FILE": "keys.json"}, clear=True):
            with self.assertRaisesRegex(ValueError, "postgresql\\+psycopg"):
                ApiSettings.from_env()
        with patch.dict(os.environ, {"DATABASE_URL": "postgresql+psycopg://user:pw@db/ares"},
                        clear=True):
            with self.assertRaisesRegex(ValueError, "ARES_API_KEYS_FILE"):
                ApiSettings.from_env()

    def test_database_password_file_is_encoded_into_postgresql_url(self):
        with tempfile.TemporaryDirectory() as directory:
            password_path = os.path.join(directory, "password")
            with open(password_path, "w", encoding="utf-8") as target:
                target.write("password with spaces\n")
            environment = {
                "DATABASE_PASSWORD_FILE": password_path,
                "DATABASE_USER": "ares",
                "DATABASE_HOST": "db.internal",
                "DATABASE_NAME": "ares",
            }
            with patch.dict(os.environ, environment, clear=True):
                url = ApiSettings.database_url_from_env()
            self.assertTrue(url.startswith("postgresql+psycopg://ares:"))
            self.assertIn("db.internal:5432/ares", url)

    def test_api_keys_are_loaded_as_digests_and_validated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "keys.json")
            with open(path, "w", encoding="utf-8") as target:
                json.dump([{"key_id": "site-one", "tenant_id": "tenant-1", "secret": SECRET}], target)
            clients = load_api_clients(path)
            self.assertEqual(len(clients), 1)
            self.assertEqual(clients[0].tenant_id, "tenant-1")
            self.assertNotEqual(clients[0].secret_digest, SECRET.encode())

            with open(path, "w", encoding="utf-8") as target:
                json.dump([{"key_id": "short", "tenant_id": "tenant-1", "secret": "short"}], target)
            with self.assertRaisesRegex(ValueError, "at least 32"):
                load_api_clients(path)

    def test_authentication_requires_bearer_and_returns_tenant(self):
        clients = load_api_clients_from_data(
            [{"key_id": "site-one", "tenant_id": "tenant-1", "secret": SECRET}])
        app = FastAPI()
        app.state.api_clients = clients
        request = Request({"type": "http", "app": app, "headers": [], "method": "GET",
                           "path": "/", "query_string": b"", "server": ("test", 80)})
        credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=SECRET)
        self.assertEqual(require_api_client(request, credentials).tenant_id, "tenant-1")
        with self.assertRaises(HTTPException) as missing:
            require_api_client(request, None)
        self.assertEqual(missing.exception.status_code, 401)
        with self.assertRaises(HTTPException) as invalid:
            require_api_client(
                request, HTTPAuthorizationCredentials(scheme="Bearer", credentials="incorrect"))
        self.assertEqual(invalid.exception.status_code, 401)

    def test_event_window_schema_rejects_extra_and_out_of_range_fields(self):
        event = ScoreRequest.model_validate_json(
            json.dumps({"event_id": str(uuid4()), "features": FEATURES}))
        self.assertEqual(event.features.protocol, "SSH")

        invalid = dict(FEATURES, destination_port=0)
        with self.assertRaises(ValidationError):
            EventFeatures.model_validate(invalid)
        with self.assertRaises(ValidationError):
            EventFeatures.model_validate(dict(FEATURES, target_ip="127.0.0.1"))

    def test_scoring_reuses_detector_and_planner_without_executing_response(self):
        detection = {
            "attack_type": "Brute Force",
            "raw_label": "Brute Force",
            "confidence": 0.9,
            "novelty": 0.2,
            "is_unknown": False,
            "unknown_reason": None,
            "risk": "HIGH",
            "probabilities": {"Brute Force": 0.9},
        }

        class FakeDetector:
            def detect(self, features, confidence_threshold, outlier_threshold):
                return detection

        with patch("api.scoring.get_detector", return_value=FakeDetector()):
            result = score_features(FEATURES, {
                "detector": {"confidence_threshold": 0.65, "outlier_threshold": 3.0}})
        self.assertEqual(result["classification"], "Brute Force")
        self.assertEqual(result["recommendation"], "BLOCK_IP")
        self.assertIn("BLOCK_IP", result["recommendation_reason"])

    def test_scoring_endpoint_persists_and_returns_idempotent_result(self):
        event_id = uuid4()
        payload = ScoreRequest.model_validate_json(
            json.dumps({"event_id": str(event_id), "features": FEATURES}))
        app = FastAPI()
        app.state.agent_settings = {
            "detector": {"confidence_threshold": 0.65, "outlier_threshold": 3.0}}
        app.state.model_version = "a" * 64
        request = Request({"type": "http", "app": app, "headers": [], "method": "POST",
                           "path": "/v1/windows/score", "query_string": b"", "server": ("test", 80)})
        client = ApiClient("tenant-1", b"digest")

        class FakeResult:
            def __init__(self, value):
                self.value = value

            def scalar_one_or_none(self):
                return self.value

            def scalar_one(self):
                return self.value

        class FakeSession:
            def __init__(self, duplicate):
                self.duplicate = duplicate
                self.calls = 0
                self.inserted_values = None

            def execute(self, statement):
                self.calls += 1
                if self.calls == 1:
                    self.inserted_values = statement.compile().params
                    return FakeResult(None if self.duplicate else uuid4())
                record = SimpleNamespace(
                    event_id=event_id, classification="Brute Force",
                    raw_classification="Brute Force", confidence=0.9,
                    novelty_distance=0.2, is_unknown=False, unknown_reason=None,
                    risk="HIGH", risk_score=79.95, recommendation="BLOCK_IP",
                    recommendation_reason="Recommendation only.", model_version="a" * 64,
                )
                return FakeResult(record)

            def commit(self):
                pass

        with patch("api.scoring.score_features", return_value={
            "classification": "Brute Force", "raw_classification": "Brute Force",
            "confidence": 0.9, "novelty_distance": 0.2, "is_unknown": False,
            "unknown_reason": None, "risk": "HIGH", "risk_score": 79.95,
            "probabilities": {"Brute Force": 0.9}, "recommendation": "BLOCK_IP",
            "recommendation_reason": "Recommendation only.",
        }):
            first_session = FakeSession(duplicate=False)
            first = score_window(payload, request, client, first_session)
            self.assertFalse(first.duplicate)
            self.assertEqual(first.classification, "Brute Force")
            self.assertEqual(first_session.inserted_values["tenant_id"], "tenant-1")

            duplicate_session = FakeSession(duplicate=True)
            duplicate = score_window(payload, request, client, duplicate_session)
            self.assertTrue(duplicate.duplicate)
            self.assertEqual(duplicate.event_id, event_id)

    def test_body_limit_rejects_oversized_content_length(self):
        messages = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)

        async def app(scope, receive, send):
            self.fail("Oversized body reached the application.")

        middleware = BodyLimitMiddleware(app, max_bytes=8)
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/windows/score",
            "headers": [(b"content-length", b"9")],
        }
        import asyncio
        asyncio.run(middleware(scope, receive, send))
        self.assertEqual(messages[0]["status"], 413)

    def test_body_limit_also_rejects_oversized_chunked_body(self):
        messages, chunks = [], iter((b"12345", b"67890"))

        async def receive():
            try:
                body = next(chunks)
            except StopIteration:
                return {"type": "http.request", "body": b"", "more_body": False}
            return {"type": "http.request", "body": body, "more_body": True}

        async def send(message):
            messages.append(message)

        async def app(scope, receive, send):
            self.fail("Oversized chunked body reached the application.")

        middleware = BodyLimitMiddleware(app, max_bytes=8)
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/windows/score",
            "headers": [(b"transfer-encoding", b"chunked")],
        }
        import asyncio
        asyncio.run(middleware(scope, receive, send))
        self.assertEqual(messages[0]["status"], 413)


def load_api_clients_from_data(entries):
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "keys.json")
        with open(path, "w", encoding="utf-8") as target:
            json.dump(entries, target)
        return load_api_clients(path)


if __name__ == "__main__":
    unittest.main()
