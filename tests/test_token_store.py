import hashlib
import time
from typing import Optional

import pytest

from auth0_api_python._internal.cache_keys import (
    index_cache_key,
    is_covered_by,
    m2m_cache_key,
    obo_cache_key,
    session_fingerprint,
    token_vault_cache_key,
)
from auth0_api_python.token_store import (
    AbstractTokenStore,
    TokenSet,
)
from auth0_api_python.token_utils import generate_token

# ===== AbstractTokenStore =====


class ConcreteTokenStore(AbstractTokenStore):
    """Minimal concrete store for testing the ABC and its helpers."""

    def __init__(self, *, secret: str = "test-secret") -> None:  # noqa: S107
        super().__init__(secret=secret)
        self._store: dict[str, str] = {}

    async def get(self, key: str) -> Optional[TokenSet]:
        raw = self._store.get(key)
        if raw is None:
            return None
        return self.decrypt(key, raw)

    async def set(self, key: str, value: TokenSet) -> None:
        self._store[key] = self.encrypt(key, value)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)


@pytest.mark.asyncio
async def test_abstract_token_store_set_then_get_roundtrip():
    """Stored value is returned correctly after an encrypt/decrypt roundtrip."""
    store = ConcreteTokenStore()
    value: TokenSet = {"access_token": "at", "expires_at": int(time.time()) + 3600}

    await store.set("key1", value)

    assert await store.get("key1") == value


@pytest.mark.asyncio
async def test_abstract_token_store_get_missing_key_returns_none():
    """get() on a missing key returns None."""
    store = ConcreteTokenStore()

    assert await store.get("missing") is None


@pytest.mark.asyncio
async def test_abstract_token_store_delete_removes_entry():
    """delete() removes a stored entry."""
    store = ConcreteTokenStore()
    value: TokenSet = {"access_token": "at", "expires_at": int(time.time()) + 3600}

    await store.set("key1", value)
    await store.delete("key1")

    assert await store.get("key1") is None


@pytest.mark.asyncio
async def test_abstract_token_store_delete_missing_key_is_noop():
    """delete() on a missing key does not raise."""
    store = ConcreteTokenStore()

    await store.delete("missing")


def test_encrypt_decrypt_roundtrip():
    """encrypt/decrypt helpers round-trip a TokenSet back to the original dict."""
    store = ConcreteTokenStore(secret="some-secret")
    value: TokenSet = {"access_token": "tok", "expires_at": 9999999}

    encrypted = store.encrypt("cache-key", value)
    decrypted = store.decrypt("cache-key", encrypted)

    assert decrypted == dict(value)


def test_encrypt_different_cache_keys_produce_different_ciphertext():
    """Two entries with the same value but different keys produce different ciphertext."""
    store = ConcreteTokenStore(secret="some-secret")
    value: TokenSet = {"access_token": "tok", "expires_at": 9999999}

    enc1 = store.encrypt("key-a", value)
    enc2 = store.encrypt("key-b", value)

    assert enc1 != enc2


def test_encrypt_different_secrets_produce_different_ciphertext():
    """Two stores with different secrets produce different ciphertext for the same payload."""
    store_a = ConcreteTokenStore(secret="secret-a")
    store_b = ConcreteTokenStore(secret="secret-b")
    value: TokenSet = {"access_token": "tok", "expires_at": 9999999}

    enc_a = store_a.encrypt("key", value)
    enc_b = store_b.encrypt("key", value)

    assert enc_a != enc_b


def test_encrypt_same_inputs_produce_different_ciphertext_each_call():
    """Each encrypt call produces unique ciphertext due to the random kid per call."""
    store = ConcreteTokenStore(secret="some-secret")
    value: TokenSet = {"access_token": "tok", "expires_at": 9999999}

    enc1 = store.encrypt("key", value)
    enc2 = store.encrypt("key", value)

    assert enc1 != enc2


# ===== obo_cache_key =====


def _obo_key(**overrides):
    """Build an obo_cache_key with sensible defaults, overriding only the field under test."""
    params = {
        "layout": "strict",
        "sub": "sub1",
        "issuer": "https://tenant.example/",
        "incoming_client_id": "incoming1",
        "exchange_tenant": "tenant.example.auth0.com",
        "exchange_client_id": "cid",
        "audience": "aud1",
        "org_id": "org1",
        "scopes": "read",
        "session_key": "sess1",
    }
    params.update(overrides)
    return obo_cache_key(**params)


def test_obo_cache_key_same_inputs_same_key():
    """Test that identical inputs produce identical cache keys."""
    assert _obo_key() == _obo_key()


def test_obo_cache_key_different_sub():
    """Test that a different sub produces a different cache key."""
    assert _obo_key(sub="sub1") != _obo_key(sub="sub2")


def test_obo_cache_key_different_audience():
    """Test that a different audience produces a different cache key."""
    assert _obo_key(audience="aud1") != _obo_key(audience="aud2")


def test_obo_cache_key_different_issuer():
    """Test that a different verified issuer produces a different cache key."""
    assert _obo_key(issuer="https://a/") != _obo_key(issuer="https://b/")


def test_obo_cache_key_different_exchange_tenant():
    """Test that a different exchange tenant produces a different cache key."""
    assert _obo_key(exchange_tenant="a.auth0.com") != _obo_key(exchange_tenant="b.auth0.com")


def test_obo_cache_key_different_exchange_client_id():
    """Test that a different exchange client_id produces a different cache key."""
    assert _obo_key(exchange_client_id="cid1") != _obo_key(exchange_client_id="cid2")


def test_obo_cache_key_different_incoming_client_id():
    """Test that two clients sharing a sub and session never share a key."""
    assert _obo_key(incoming_client_id="app1") != _obo_key(incoming_client_id="app2")


def test_obo_cache_key_different_layout():
    """Test that the strict and index layouts never share a key for the same fields."""
    assert _obo_key(layout="strict") != _obo_key(layout="index")


def test_obo_cache_key_none_org_id_matches_empty_string_org_id():
    """Test that org_id=None and org_id="" both represent an absent org and share a key."""
    assert _obo_key(org_id=None) == _obo_key(org_id="")


def test_obo_cache_key_absent_org_differs_from_real_org():
    """Test that an absent org_id (None/"") produces a different key than a real org_id."""
    assert _obo_key(org_id=None) != _obo_key(org_id="org_abc123")


def test_obo_cache_key_scope_order_and_duplicates_do_not_matter():
    """Test that scope order and duplicates normalize to the same cache key."""
    base = _obo_key(scopes="a b")

    assert _obo_key(scopes="b a") == base
    assert _obo_key(scopes="a a b") == base


def test_obo_cache_key_different_scopes():
    """Test that a different scope set produces a different cache key."""
    assert _obo_key(scopes="read") != _obo_key(scopes="read write")


def test_obo_cache_key_different_session_key():
    """Test that a different session_key produces a different cache key."""
    assert _obo_key(session_key="sess1") != _obo_key(session_key="sess2")


# ===== m2m_cache_key =====


def _m2m_key(**overrides):
    """Build an m2m_cache_key with sensible defaults, overriding only the field under test."""
    params = {"tenant": "tenant.auth0.com", "client_id": "cid", "audience": "aud1", "scopes": "read"}
    params.update(overrides)
    return m2m_cache_key(**params)


def test_m2m_cache_key_same_inputs_same_key():
    """Test that identical inputs produce identical cache keys."""
    assert _m2m_key() == _m2m_key()


def test_m2m_cache_key_different_inputs_different_key():
    """Test that a different tenant, client, audience, or scope produces a different cache key."""
    base = _m2m_key()

    assert _m2m_key(tenant="other.auth0.com") != base
    assert _m2m_key(client_id="cid2") != base
    assert _m2m_key(audience="aud2") != base
    assert _m2m_key(scopes="write") != base


# ===== token_vault_cache_key =====


def test_token_vault_cache_key_same_inputs_same_key():
    """Test that identical inputs produce identical cache keys."""
    assert token_vault_cache_key("sub1", "conn1") == token_vault_cache_key("sub1", "conn1")


def test_token_vault_cache_key_different_inputs_different_key():
    """Test that a different sub or connection produces a different cache key."""
    base = token_vault_cache_key("sub1", "conn1")

    assert token_vault_cache_key("sub2", "conn1") != base
    assert token_vault_cache_key("sub1", "conn2") != base


# ===== session_fingerprint =====


@pytest.mark.asyncio
async def test_session_fingerprint_uses_sid_when_present():
    """Test that a token with a sid claim returns the sid as the fingerprint."""
    token = await generate_token(
        domain="auth0.local",
        user_id="user1",
        claims={"sid": "session-abc"},
    )

    assert session_fingerprint(token) == "session-abc"


@pytest.mark.asyncio
async def test_session_fingerprint_falls_back_to_jti_when_no_sid():
    """Test that a token with no sid but a jti returns the jti as the fingerprint."""
    token = await generate_token(
        domain="auth0.local",
        user_id="user1",
        claims={"jti": "jwt-id-123"},
    )

    assert session_fingerprint(token) == "jwt-id-123"


@pytest.mark.asyncio
async def test_session_fingerprint_falls_back_to_sha256_when_no_sid_or_jti():
    """Test that a token with neither sid nor jti falls back to a sha256 digest of the token."""
    token = await generate_token(
        domain="auth0.local",
        user_id="user1",
    )

    expected = hashlib.sha256(token.encode()).hexdigest()

    assert session_fingerprint(token) == expected


def test_session_fingerprint_falls_back_to_sha256_for_malformed_token():
    """Test that a malformed, non-JWT string falls back to a sha256 digest without raising."""
    malformed = "not-a-real-token"

    expected = hashlib.sha256(malformed.encode()).hexdigest()

    assert session_fingerprint(malformed) == expected


# ===== is_covered_by =====


def test_is_covered_by_exact_match():
    """Identical granted and requested sets are covered."""
    assert is_covered_by("read:x write:x", "read:x write:x") is True


def test_is_covered_by_superset_granted():
    """Granted superset covers a requested subset."""
    assert is_covered_by("read:x", "read:x write:x") is True


def test_is_covered_by_insufficient_granted():
    """Granted does not cover a request that requires more scopes."""
    assert is_covered_by("read:x write:x", "read:x") is False


def test_is_covered_by_both_none():
    """None/None is covered (no scopes requested, none granted)."""
    assert is_covered_by(None, None) is True


def test_is_covered_by_none_granted_nonempty_requested():
    """Empty granted does not cover a non-empty request."""
    assert is_covered_by("read:x", None) is False


def test_is_covered_by_order_and_duplicates_do_not_matter():
    """Scope order and duplicates are normalized before comparison."""
    assert is_covered_by("a b", "b a a") is True


# ===== index_cache_key =====


def _idx_key(**overrides):
    """Build an index_cache_key with sensible defaults, overriding only the field under test."""
    params = {
        "sub": "sub1",
        "issuer": "https://tenant.example/",
        "incoming_client_id": "incoming1",
        "exchange_tenant": "tenant.example.auth0.com",
        "exchange_client_id": "cid",
        "audience": "aud1",
        "org_id": "org1",
        "session_key": "sess1",
    }
    params.update(overrides)
    return index_cache_key(**params)


def test_index_cache_key_same_inputs_same_key():
    """index_cache_key is deterministic."""
    assert _idx_key() == _idx_key()


def test_index_cache_key_differs_from_obo_cache_key():
    """index_cache_key never collides with either token layout for the same fields."""
    idx = _idx_key()
    assert idx != _obo_key(layout="index", scopes=None)
    assert idx != _obo_key(layout="strict", scopes=None)


def test_index_cache_key_different_sub():
    """Different sub produces a different index key."""
    assert _idx_key(sub="sub1") != _idx_key(sub="sub2")


def test_index_cache_key_different_audience():
    """Different audience produces a different index key."""
    assert _idx_key(audience="aud1") != _idx_key(audience="aud2")


def test_index_cache_key_different_issuer():
    """Different verified issuer produces a different index key."""
    assert _idx_key(issuer="https://a/") != _idx_key(issuer="https://b/")


def test_index_cache_key_different_exchange_tenant():
    """Different exchange tenant produces a different index key."""
    assert _idx_key(exchange_tenant="a.auth0.com") != _idx_key(exchange_tenant="b.auth0.com")


def test_index_cache_key_different_exchange_client_id():
    """Different exchange client_id produces a different index key."""
    assert _idx_key(exchange_client_id="cid1") != _idx_key(exchange_client_id="cid2")


def test_index_cache_key_different_incoming_client_id():
    """Two clients sharing a sub and session never share an index key."""
    assert _idx_key(incoming_client_id="app1") != _idx_key(incoming_client_id="app2")


def test_index_cache_key_none_org_matches_empty_string():
    """None and empty org_id produce the same index key."""
    assert _idx_key(org_id=None) == _idx_key(org_id="")


def test_index_cache_key_different_session():
    """Different session fingerprint produces a different index key."""
    assert _idx_key(session_key="sess1") != _idx_key(session_key="sess2")
