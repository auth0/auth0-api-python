"""
Client telemetry headers sent on every request this SDK makes to Auth0.
"""

import base64
import importlib.metadata
import json
import platform
from typing import Optional

_PACKAGE_NAME = "auth0-api-python"


def _package_version() -> str:
    try:
        return importlib.metadata.version(_PACKAGE_NAME)
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def validate_client_info(client_info: dict) -> None:
    """
    Check the shape of a wrapper's client_info.

    Raises:
        ValueError: If client_info is not a dict with non-empty string name and version, and an optional env dict of strings.
    """
    if not isinstance(client_info, dict):
        raise ValueError("client_info must be a dict")
    for key in ("name", "version"):
        value = client_info.get(key)
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"client_info['{key}'] must be a non-empty string")
    env = client_info.get("env", {})
    if not isinstance(env, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        raise ValueError("client_info['env'] must be a dict of string keys and string values")


def build_telemetry_headers(client_info: Optional[dict] = None) -> dict[str, str]:
    """
    Build the Auth0-Client and User-Agent headers.

    Args:
        client_info: Name, version and optional env of a wrapper SDK built on this one.

    Returns:
        Headers to attach to each HTTP request.
    """
    core_version = _package_version()
    python_version = platform.python_version()

    if client_info is None:
        payload = {"name": _PACKAGE_NAME, "version": core_version, "env": {"python": python_version}}
    else:
        env = {**client_info.get("env", {}), "python": python_version, _PACKAGE_NAME: core_version}
        payload = {"name": client_info["name"], "version": client_info["version"], "env": env}

    return {
        "Auth0-Client": base64.b64encode(json.dumps(payload).encode("utf-8")).decode("utf-8"),
        "User-Agent": f"Python/{python_version}",
    }
