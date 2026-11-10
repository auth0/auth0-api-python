"""
Tests for the Auth0-Client telemetry header built in auth0_api_python.telemetry
"""

import base64
import importlib.metadata
import json
import platform
import re

import pytest
from conftest import TOKEN_ENDPOINT, auth0_client_payload, token_success
from pytest_httpx import HTTPXMock

from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import ConfigurationError
from auth0_api_python.telemetry import build_telemetry_headers, validate_client_info

WRAPPER = {"name": "auth0-ai-fastmcp", "version": "1.2.3", "env": {"auth0-ai-mcp": "4.5.6"}}


@pytest.fixture
def core_version(monkeypatch):
    monkeypatch.setattr(importlib.metadata, "version", lambda name: "9.9.9")
    return "9.9.9"


def _decode(headers: dict) -> dict:
    return json.loads(base64.b64decode(headers["Auth0-Client"]))


# ===== build_telemetry_headers =====


def test_default_headers_identify_this_sdk(core_version):
    headers = build_telemetry_headers()

    assert _decode(headers) == {
        "name": "auth0-api-python",
        "version": core_version,
        "env": {"python": platform.python_version()},
    }
    assert headers["User-Agent"] == f"Python/{platform.python_version()}"


def test_version_is_unknown_when_package_is_not_installed(monkeypatch):
    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)

    assert _decode(build_telemetry_headers())["version"] == "unknown"


def test_client_info_is_reported_as_the_client_and_this_sdk_is_listed_in_env(core_version):
    payload = _decode(build_telemetry_headers(WRAPPER))

    assert payload["name"] == "auth0-ai-fastmcp"
    assert payload["version"] == "1.2.3"
    assert payload["env"] == {
        "auth0-ai-mcp": "4.5.6",
        "python": platform.python_version(),
        "auth0-api-python": core_version,
    }


def test_client_info_env_cannot_replace_this_sdk_or_python_entries(core_version):
    payload = _decode(build_telemetry_headers({**WRAPPER, "env": {"auth0-api-python": "0.0.0", "python": "0.0"}}))

    assert payload["env"]["auth0-api-python"] == core_version
    assert payload["env"]["python"] == platform.python_version()


def test_client_info_without_env_is_accepted(core_version):
    payload = _decode(build_telemetry_headers({"name": "wrapper", "version": "1.0.0"}))

    assert payload["env"]["auth0-api-python"] == core_version


# ===== validate_client_info =====


NOT_A_DICT = "client_info must be a dict"
BAD_NAME = "client_info['name'] must be a non-empty string"
BAD_VERSION = "client_info['version'] must be a non-empty string"
BAD_ENV = "client_info['env'] must be a dict of string keys and string values"

INVALID_CLIENT_INFO = [
    ("wrapper", NOT_A_DICT),
    ([], NOT_A_DICT),
    ({}, BAD_NAME),
    ({"version": "1.0.0"}, BAD_NAME),
    ({"name": "", "version": "1.0.0"}, BAD_NAME),
    ({"name": 1, "version": "1.0.0"}, BAD_NAME),
    ({"name": "wrapper"}, BAD_VERSION),
    ({"name": "wrapper", "version": "  "}, BAD_VERSION),
    ({"name": "wrapper", "version": "1.0.0", "env": "python"}, BAD_ENV),
    ({"name": "wrapper", "version": "1.0.0", "env": None}, BAD_ENV),
    ({"name": "wrapper", "version": "1.0.0", "env": {"python": 3}}, BAD_ENV),
    ({"name": "wrapper", "version": "1.0.0", "env": {1: "x"}}, BAD_ENV),
]


@pytest.mark.parametrize(("client_info", "message"), INVALID_CLIENT_INFO)
def test_validate_client_info_rejects_malformed_input(client_info, message):
    with pytest.raises(ValueError, match=re.escape(message)):
        validate_client_info(client_info)


@pytest.mark.parametrize(("client_info", "message"), INVALID_CLIENT_INFO)
def test_api_client_rejects_malformed_client_info(client_info, message):
    with pytest.raises(ConfigurationError, match=re.escape(message)):
        ApiClient(ApiClientOptions(domain="auth0.local", audience="my-audience", client_info=client_info))


# ===== ApiClientOptions.client_info =====


@pytest.mark.asyncio
async def test_client_info_reaches_the_token_endpoint(core_version, mock_discovery, httpx_mock: HTTPXMock):
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
    assert payload["env"]["auth0-api-python"] == core_version
