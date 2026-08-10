import asyncio

import pytest
import pytest_asyncio
from conftest import DISCOVERY_URL, JWKS_URL
from pytest_httpx import HTTPXMock

from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python import utils as auth0_utils

# ===== Fixtures =====

@pytest_asyncio.fixture(autouse=True)
async def _reset_default_httpx_client():
    await auth0_utils.aclose_default_httpx_client()
    yield
    await auth0_utils.aclose_default_httpx_client()


# ===== Single-flight: JWKS =====

@pytest.mark.asyncio
async def test_concurrent_jwks_misses_trigger_single_fetch(httpx_mock: HTTPXMock):
    """N concurrent JWKS cache misses for the same URI cause exactly one upstream fetch."""
    httpx_mock.add_response(
        method="GET",
        url=JWKS_URL,
        json={"keys": []},
        is_reusable=True,
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    results = await asyncio.gather(
        *(api_client._fetch_jwks(JWKS_URL) for _ in range(50))
    )

    assert all(r == {"keys": []} for r in results)
    requests = [r for r in httpx_mock.get_requests() if str(r.url) == JWKS_URL]
    assert len(requests) == 1


# ===== Single-flight: OIDC discovery =====

@pytest.mark.asyncio
async def test_concurrent_oidc_misses_trigger_single_fetch(httpx_mock: HTTPXMock):
    """N concurrent OIDC discovery cache misses cause exactly one upstream fetch."""
    httpx_mock.add_response(
        method="GET",
        url=DISCOVERY_URL,
        json={"issuer": "https://auth0.local/", "jwks_uri": JWKS_URL},
        is_reusable=True,
    )

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    results = await asyncio.gather(
        *(api_client._discover() for _ in range(50))
    )

    expected = {"issuer": "https://auth0.local/", "jwks_uri": JWKS_URL}
    assert all(r == expected for r in results)
    requests = [r for r in httpx_mock.get_requests() if str(r.url) == DISCOVERY_URL]
    assert len(requests) == 1


# ===== Per-key locking =====

@pytest.mark.asyncio
async def test_jwks_locks_are_per_cache_key(httpx_mock: HTTPXMock):
    """Concurrent misses for different JWKS URIs are not serialized behind one global lock."""
    uri_a = "https://a.auth0.local/.well-known/jwks.json"
    uri_b = "https://b.auth0.local/.well-known/jwks.json"
    httpx_mock.add_response(method="GET", url=uri_a, json={"keys": ["a"]})
    httpx_mock.add_response(method="GET", url=uri_b, json={"keys": ["b"]})

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )

    a, b = await asyncio.gather(
        api_client._fetch_jwks(uri_a),
        api_client._fetch_jwks(uri_b),
    )

    assert a == {"keys": ["a"]}
    assert b == {"keys": ["b"]}

    requests_a = [r for r in httpx_mock.get_requests() if str(r.url) == uri_a]
    requests_b = [r for r in httpx_mock.get_requests() if str(r.url) == uri_b]
    assert len(requests_a) == 1
    assert len(requests_b) == 1


# ===== Default httpx client =====

@pytest.mark.asyncio
async def test_default_httpx_client_is_shared():
    """The default httpx client is a singleton across calls."""
    first = await auth0_utils._get_default_httpx_client()
    second = await auth0_utils._get_default_httpx_client()

    assert first is second


@pytest.mark.asyncio
async def test_default_httpx_client_has_explicit_timeouts():
    """The default httpx client sets explicit, non-default timeouts."""
    client = await auth0_utils._get_default_httpx_client()

    assert client.timeout.connect is not None
    assert client.timeout.read is not None
    assert client.timeout.write is not None
    assert client.timeout.pool is not None
    assert client.timeout.read >= 5.0


# ===== Shutdown =====

@pytest.mark.asyncio
async def test_aclose_is_idempotent():
    """`aclose()` is safe to call repeatedly and the client can be re-created afterward."""
    await auth0_utils.aclose_default_httpx_client()
    await auth0_utils.aclose_default_httpx_client()

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )
    await api_client.aclose()
    await api_client.aclose()  # idempotent

    new_client = await auth0_utils._get_default_httpx_client()
    assert not new_client.is_closed
