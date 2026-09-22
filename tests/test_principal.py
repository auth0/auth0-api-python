import time

import pytest

from auth0_api_python import Principal, build_principal
from auth0_api_python.errors import VerifyAccessTokenError


def test_build_principal_with_all_claims_present():
    claims = {
        "sub": "auth0|user123",
        "exp": int(time.time()) + 3600,
        "scope": "calendar:read calendar:write",
        "permissions": ["calendar:read", "calendar:write"],
        "client_id": "my_client_id",
        "org_id": "org_abc123",
    }

    principal = build_principal(claims)

    assert principal == Principal(
        sub="auth0|user123",
        expires_at=claims["exp"],
        scopes=["calendar:read", "calendar:write"],
        permissions=["calendar:read", "calendar:write"],
        client_id="my_client_id",
        org_id="org_abc123",
    )


def test_build_principal_missing_org_id():
    claims = {
        "sub": "auth0|user123",
        "exp": int(time.time()) + 3600,
    }

    principal = build_principal(claims)

    assert principal.org_id is None


def test_build_principal_missing_permissions_is_none():
    claims = {
        "sub": "auth0|user123",
        "exp": int(time.time()) + 3600,
    }

    principal = build_principal(claims)

    assert principal.permissions is None


def test_build_principal_permissions_present_but_empty():
    claims = {
        "sub": "auth0|user123",
        "exp": int(time.time()) + 3600,
        "permissions": [],
    }

    principal = build_principal(claims)

    assert principal.permissions == []


def test_build_principal_missing_both_org_id_and_permissions():
    claims = {
        "sub": "auth0|user123",
        "exp": int(time.time()) + 3600,
    }

    principal = build_principal(claims)

    assert principal.org_id is None
    assert principal.permissions is None


def test_build_principal_client_id_falls_back_to_azp():
    claims = {
        "sub": "auth0|user123",
        "exp": int(time.time()) + 3600,
        "azp": "spa_client_id",
    }

    principal = build_principal(claims)

    assert principal.client_id == "spa_client_id"


def test_build_principal_missing_scope_claim_yields_empty_list():
    claims = {
        "sub": "auth0|user123",
        "exp": int(time.time()) + 3600,
    }

    principal = build_principal(claims)

    assert principal.scopes == []


def test_build_principal_rejects_missing_sub():
    claims = {
        "exp": int(time.time()) + 3600,
    }

    with pytest.raises(VerifyAccessTokenError, match="sub"):
        build_principal(claims)
