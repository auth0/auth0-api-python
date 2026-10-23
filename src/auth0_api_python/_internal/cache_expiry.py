"""Freshness rule shared by every cache of a token the SDK minted."""

# A token this close to expiry is treated as expired, so it is unlikely to lapse before the caller uses it.
EXPIRY_BUFFER_SECONDS = 30


def is_fresh(expires_at: int, now: int) -> bool:
    """True when a cached token still has more than the expiry buffer left."""
    return expires_at - EXPIRY_BUFFER_SECONDS > now
