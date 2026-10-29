"""
Tests for the Auth0-Client telemetry header built in auth0_api_python.telemetry
"""

import base64
import importlib.metadata
import json
import platform

import pytest
from conftest import TOKEN_ENDPOINT, auth0_client_payload, token_success
from pytest_httpx import HTTPXMock

from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import ConfigurationError
from auth0_api_python.telemetry import build_telemetry_headers, validate_client_info

WRAPPER = {"name": "auth0-ai-fastmcp", "version": "1.2.3", "env": {"auth0-ai-mcp": "4.5.6"}}


def _decode(headers: dict) -> dict:
    return json.loads(base64.b64decode(headers["Auth0-Client"]))


# ===== build_telemetry_headers =====


def test_default_headers_identify_this_sdk():
    headers = build_telemetry_headers()

    assert _decode(headers) == {
        "name": "auth0-api-python",
        "version": importlib.metadata.version("auth0-api-python"),
        "env": {"python": platform.python_version()},
    }
    assert headers["User-Agent"] == f"Python/{platform.python_version()}"


def test_version_is_unknown_when_package_is_not_installed(monkeypatch):
    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)

    assert _decode(build_telemetry_headers())["version"] == "unknown"


def test_client_info_is_reported_as_the_client_and_this_sdk_is_listed_in_env():
    payload = _decode(build_telemetry_headers(WRAPPER))

    assert payload["name"] == "auth0-ai-fastmcp"
    assert payload["version"] == "1.2.3"
    assert payload["env"] == {
        "auth0-ai-mcp": "4.5.6",
        "python": platform.python_version(),
        "auth0-api-python": importlib.metadata.version("auth0-api-python"),
    }


def test_client_info_env_cannot_replace_this_sdk_or_python_entries():
    payload = _decode(build_telemetry_headers({**WRAPPER, "env": {"auth0-api-python": "0.0.0", "python": "0.0"}}))

    assert payload["env"]["auth0-api-python"] == importlib.metadata.version("auth0-api-python")
    assert payload["env"]["python"] == platform.python_version()


def test_client_info_without_env_is_accepted():
    payload = _decode(build_telemetry_headers({"name": "wrapper", "version": "1.0.0"}))

    assert payload["env"]["auth0-api-python"] == importlib.metadata.version("auth0-api-python")


# ===== validate_client_info =====


@pytest.mark.parametrize(
    "client_info",
    [
        "wrapper",
        {"version": "1.0.0"},
        {"name": "wrapper"},
        {"name": "", "version": "1.0.0"},
        {"name": "wrapper", "version": "  "},
        {"name": 1, "version": "1.0.0"},
        {"name": "wrapper", "version": "1.0.0", "env": "python"},
        {"name": "wrapper", "version": "1.0.0", "env": {"python": 3}},
        {"name": "wrapper", "version": "1.0.0", "env": {1: "x"}},
    ],
)
def test_validate_client_info_rejects_malformed_input(client_info):
    with pytest.raises(ValueError):
        validate_client_info(client_info)


def test_api_client_rejects_malformed_client_info():
    with pytest.raises(ConfigurationError, match="client_info"):
        ApiClient(ApiClientOptions(domain="auth0.local", audience="my-audience", client_info={"name": "wrapper"}))


# ===== ApiClientOptions.client_info =====


@pytest.mark.asyncio
async def test_client_info_reaches_the_token_endpoint(mock_discovery, httpx_mock: HTTPXMock):
    httpx_mock.add_response(method="POST", url=TOKEN_ENDPOINT, json=token_success())
    api_client = ApiClient(ApiClientOptions(
        domain="auth0.local",
        audience="my-audience",
        client_id="cid",
        client_secret="csecret",
        client_info=WRAPPER,
    ))

    await api_client.get_client_credentials_token(audience="https://billing-api.example.com")

    request = httpx_mock.get_requests()[-1]
    payload = auth0_client_payload(request)
    assert request.headers["User-Agent"] == f"Python/{platform.python_version()}"
    assert payload["name"] == "auth0-ai-fastmcp"
    assert payload["version"] == "1.2.3"
    assert payload["env"]["auth0-api-python"] == importlib.metadata.version("auth0-api-python")
