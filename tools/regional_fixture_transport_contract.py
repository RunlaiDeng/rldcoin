"""Validate the original finite ground controller's observed transport limits.

This is a controller guard only. A matching observation grants no custody,
Native ledger, signing, maturity, freshness or fault-profile qualification.
Keep this contract independent of height substitutions in fixture drivers.
"""
from collections.abc import Mapping

# Fixed acceptance parameters, independent of a Runtime's current constants.
EXPECTED_LIMITS = (
    ("inbound_workers", 2),
    ("local_attempt_seconds", 3.0),
    ("local_lock_wait_seconds", 0.2),
)


def verify_original_limits(limits):
    """Refuse missing, mistyped or changed original controller parameters."""
    if not isinstance(limits, Mapping):
        raise ValueError("ground transport limits must be an observation map")
    for name, expected in EXPECTED_LIMITS:
        value = limits.get(name)
        numeric_type = type(value) is int if type(expected) is int else type(value) in (int, float)
        if not numeric_type or value != expected:
            raise ValueError(f"original ground transport limit differs: {name}")
