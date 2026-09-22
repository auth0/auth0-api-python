"""Optional local allowlist of downstream API audiences a server may exchange tokens for.

Auth0 (via the OBO client's grants) is the authoritative enforcer - it decides which audiences
and scopes can be issued. This registry is a convenience guard only: it fails fast on an
unlisted audience before any network call is made, so misconfigured callers get an immediate
local error rather than a round-trip rejection.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DownstreamApi:
    """A downstream API identified by its audience URI."""

    audience: str


class ApiRegistry:
    """Lookup table for allowed downstream APIs, keyed by audience."""

    def __init__(self, apis: list[DownstreamApi]) -> None:
        self._map: dict[str, DownstreamApi] = {api.audience: api for api in apis}

    def get(self, audience: str) -> DownstreamApi | None:
        """Return the entry for the given audience, or None if it is not registered."""
        return self._map.get(audience)
