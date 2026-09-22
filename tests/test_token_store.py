import hashlib
import time
from typing import Optional

import pytest

from auth0_api_python.token_store import (
    AbstractTokenStore,
    TokenSet,
    m2m_cache_key,
    obo_cache_key,
    session_fingerprint,
    token_vault_cache_key,
)
from auth0_api_python.token_utils import generate_token

# ===== AbstractTokenStore =====


class _ConcreteTokenStore(AbstractTokenStore):
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
    store = _ConcreteTokenStore()
    value: TokenSet = {"access_token": "at", "expires_at": int(time.time()) + 3600}

    await store.set("key1", value)

    assert await store.get("key1") == value


@pytest.mark.asyncio
async def test_abstract_token_store_get_missing_key_returns_none():
    """get() on a missing key returns None."""
    store = _ConcreteTokenStore()

    assert await store.get("missing") is None


@pytest.mark.asyncio
async def test_abstract_token_store_delete_removes_entry():
    """delete() removes a stored entry."""
    store = _ConcreteTokenStore()
    value: TokenSet = {"access_token": "at", "expires_at": int(time.time()) + 3600}

    await store.set("key1", value)
    await store.delete("key1")

    assert await store.get("key1") is None


@pytest.mark.asyncio
async def test_abstract_token_store_delete_missing_key_is_noop():
    """delete() on a missing key does not raise."""
    store = _ConcreteTokenStore()

    await store.delete("missing")


def test_encrypt_decrypt_roundtrip():
    """encrypt/decrypt helpers round-trip a TokenSet back to the original dict."""
    store = _ConcreteTokenStore(secret="some-secret")
    value: TokenSet = {"access_token": "tok", "expires_at": 9999999}

    encrypted = store.encrypt("cache-key", value)
    decrypted = store.decrypt("cache-key", encrypted)

    assert decrypted == dict(value)


def test_encrypt_different_cache_keys_produce_different_ciphertext():
    """Two entries with the same value but different keys produce different ciphertext."""
    store = _ConcreteTokenStore(secret="some-secret")
    value: TokenSet = {"access_token": "tok", "expires_at": 9999999}

    enc1 = store.encrypt("key-a", value)
    enc2 = store.encrypt("key-b", value)

    assert enc1 != enc2


def test_encrypt_different_secrets_produce_different_ciphertext():
    """Two stores with different secrets produce different ciphertext for the same payload."""
    store_a = _ConcreteTokenStore(secret="secret-a")
    store_b = _ConcreteTokenStore(secret="secret-b")
    value: TokenSet = {"access_token": "tok", "expires_at": 9999999}

    enc_a = store_a.encrypt("key", value)
    enc_b = store_b.encrypt("key", value)

    assert enc_a != enc_b


def test_encrypt_same_inputs_produce_different_ciphertext_each_call():
    """Each encrypt call produces unique ciphertext due to the random kid per call."""
    store = _ConcreteTokenStore(secret="some-secret")
    value: TokenSet = {"access_token": "tok", "expires_at": 9999999}

    enc1 = store.encrypt("key", value)
    enc2 = store.encrypt("key", value)

    assert enc1 != enc2


# ===== obo_cache_key =====


def test_obo_cache_key_same_inputs_same_key():
    """Test that identical inputs produce identical cache keys."""
    key1 = obo_cache_key("sub1", "aud1", "org1", "read", "sess1")
    key2 = obo_cache_key("sub1", "aud1", "org1", "read", "sess1")

    assert key1 == key2


def test_obo_cache_key_different_sub():
    """Test that a different sub produces a different cache key."""
    key1 = obo_cache_key("sub1", "aud1", "org1", "read", "sess1")
    key2 = obo_cache_key("sub2", "aud1", "org1", "read", "sess1")

    assert key1 != key2


def test_obo_cache_key_different_audience():
    """Test that a different audience produces a different cache key."""
    key1 = obo_cache_key("sub1", "aud1", "org1", "read", "sess1")
    key2 = obo_cache_key("sub1", "aud2", "org1", "read", "sess1")

    assert key1 != key2


def test_obo_cache_key_none_org_id_matches_empty_string_org_id():
    """Test that org_id=None and org_id="" both represent an absent org and share a key."""
    key_none = obo_cache_key("sub1", "aud1", None, "read", "sess1")
    key_empty = obo_cache_key("sub1", "aud1", "", "read", "sess1")

    assert key_none == key_empty


def test_obo_cache_key_absent_org_differs_from_real_org():
    """Test that an absent org_id (None/"") produces a different key than a real org_id."""
    key_absent = obo_cache_key("sub1", "aud1", None, "read", "sess1")
    key_real = obo_cache_key("sub1", "aud1", "org_abc123", "read", "sess1")

    assert key_absent != key_real


def test_obo_cache_key_scope_order_and_duplicates_do_not_matter():
    """Test that scope order and duplicates normalize to the same cache key."""
    base = obo_cache_key("sub1", "aud1", "org1", "a b", "sess1")

    assert obo_cache_key("sub1", "aud1", "org1", "b a", "sess1") == base
    assert obo_cache_key("sub1", "aud1", "org1", "a a b", "sess1") == base


def test_obo_cache_key_different_session_key():
    """Test that a different session_key produces a different cache key."""
    key1 = obo_cache_key("sub1", "aud1", "org1", "read", "sess1")
    key2 = obo_cache_key("sub1", "aud1", "org1", "read", "sess2")

    assert key1 != key2


# ===== m2m_cache_key =====


def test_m2m_cache_key_same_inputs_same_key():
    """Test that identical inputs produce identical cache keys."""
    assert m2m_cache_key("aud1", "read") == m2m_cache_key("aud1", "read")


def test_m2m_cache_key_different_inputs_different_key():
    """Test that a different audience or scope produces a different cache key."""
    base = m2m_cache_key("aud1", "read")

    assert m2m_cache_key("aud2", "read") != base
    assert m2m_cache_key("aud1", "write") != base


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
