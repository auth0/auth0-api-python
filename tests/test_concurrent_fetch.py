"""
Tests for the shared default httpx client and per-cache-key
single-flight refetch behaviour in `ApiClient`.

Guards two fixes:

1. The default httpx client used by `utils.fetch_jwks` /
   `utils.fetch_oidc_metadata` (when no `custom_fetch` is supplied) is a
   single shared instance with explicit timeouts — not a fresh
   `httpx.AsyncClient()` per call relying on httpx's 5-second defaults.

2. Per-cache-key single-flight on `ApiClient._fetch_jwks` and
   `ApiClient._discover`: N concurrent cache misses for the same key
   produce exactly ONE upstream HTTP fetch.
"""

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
    """Ensure each test starts and ends with no shared httpx client.

    The shared client is built lazily on first use; resetting it before
    each test guarantees it is (re)created inside the active
    `httpx_mock` patch scope, so pytest-httpx can intercept its
    requests.
    """
    await auth0_utils.aclose_default_httpx_client()
    yield
    await auth0_utils.aclose_default_httpx_client()


# ===== Single-flight: JWKS =====

@pytest.mark.asyncio
async def test_concurrent_jwks_misses_trigger_single_fetch(httpx_mock: HTTPXMock):
    """
    Test that 50 concurrent callers missing the JWKS cache for the same
    URI cause exactly one outbound HTTP fetch, not 50.
    """
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
    assert len(requests) == 1, (
        f"Expected exactly 1 outbound JWKS fetch under concurrent miss, "
        f"got {len(requests)}"
    )


# ===== Single-flight: OIDC discovery =====

@pytest.mark.asyncio
async def test_concurrent_oidc_misses_trigger_single_fetch(httpx_mock: HTTPXMock):
    """
    Test that 50 concurrent callers missing the OIDC discovery cache
    cause exactly one outbound HTTP fetch, not 50.
    """
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
    assert len(requests) == 1, (
        f"Expected exactly 1 outbound OIDC discovery fetch under "
        f"concurrent miss, got {len(requests)}"
    )


# ===== Per-key locking =====

@pytest.mark.asyncio
async def test_jwks_locks_are_per_cache_key(httpx_mock: HTTPXMock):
    """
    Test that concurrent misses for DIFFERENT JWKS URIs are not
    serialized behind a single global lock — each URI gets its own.
    """
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
    """
    Test that the default httpx client is a singleton across calls when
    no `custom_fetch` is supplied — not a fresh client per call.
    """
    first = await auth0_utils._get_default_httpx_client()
    second = await auth0_utils._get_default_httpx_client()

    assert first is second, "default httpx client should be a singleton"


@pytest.mark.asyncio
async def test_default_httpx_client_has_explicit_timeouts():
    """
    Test that the default httpx client has explicit, non-default
    timeouts. Regression guard: httpx's default 5-second timeouts
    fall over under concurrent load.
    """
    client = await auth0_utils._get_default_httpx_client()

    assert client.timeout.connect is not None
    assert client.timeout.read is not None
    assert client.timeout.write is not None
    assert client.timeout.pool is not None
    # Read timeout in particular should be generous (>= 5s).
    assert client.timeout.read >= 5.0


# ===== Shutdown =====

@pytest.mark.asyncio
async def test_aclose_is_idempotent():
    """
    Test that `ApiClient.aclose()` and `aclose_default_httpx_client()`
    are safe to call multiple times — including before the client was
    ever created — and that the client can be re-created after close.
    """
    # Safe to call before the client is ever built.
    await auth0_utils.aclose_default_httpx_client()
    await auth0_utils.aclose_default_httpx_client()

    api_client = ApiClient(
        ApiClientOptions(domain="auth0.local", audience="my-audience")
    )
    await api_client.aclose()
    await api_client.aclose()  # idempotent

    # Closed client must be re-creatable on next use.
    new_client = await auth0_utils._get_default_httpx_client()
    assert not new_client.is_closed
