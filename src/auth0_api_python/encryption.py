"""JWE encryption helpers for token store implementations."""

from __future__ import annotations

import base64
import json
import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from jwcrypto import jwe, jwk
from jwcrypto.common import base64url_encode

_ENC = "A256CBC-HS512"
_ALG = "dir"
_KEY_LENGTH = 64
_INFO = b"Auth0 Generated Encryption"


def _derive_key(secret: bytes, salt: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        info=_INFO,
    ).derive(secret)


def _read_jwe_kid(token: str) -> str:
    """Extract the kid from a compact JWE protected header."""
    header_b64 = token.split(".")[0]
    padding = 4 - len(header_b64) % 4
    if padding != 4:
        header_b64 += "=" * padding
    header = json.loads(base64.urlsafe_b64decode(header_b64))
    kid = header.get("kid")
    if not kid:
        raise ValueError('Missing "kid" in JWE header')
    return kid


def encrypt(payload: dict[str, Any], secret: str, salt: str) -> str:
    """Encrypt a dict to a compact JWE string. A fresh random kid is generated per call."""
    kid = str(uuid.uuid4())
    key_bytes = _derive_key(secret.encode(), f"{salt}{kid}".encode())
    key = jwk.JWK(k=base64url_encode(key_bytes), kty="oct")
    token = jwe.JWE(json.dumps(payload), protected={"alg": _ALG, "enc": _ENC, "kid": kid})
    token.add_recipient(key)
    return token.serialize(compact=True)


def decrypt(data: str, secret: str, salt: str) -> dict[str, Any]:
    """Decrypt a compact JWE string back to a dict."""
    kid = _read_jwe_kid(data)
    key_bytes = _derive_key(secret.encode(), f"{salt}{kid}".encode())
    key = jwk.JWK(k=base64url_encode(key_bytes), kty="oct")
    token = jwe.JWE()
    token.deserialize(data)
    token.decrypt(key)
    return json.loads(token.payload.decode())
