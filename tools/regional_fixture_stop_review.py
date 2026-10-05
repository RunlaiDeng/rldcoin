"""Finite controller stop requests from observations, without Native authority.

Transport retry diagnostics do not invalidate an already observed native mature
output. They also do not establish custody or value. Eligibility requests only
graceful stopping; full cold Native/envelope/head/owner checks remain mandatory.
"""
from collections.abc import Mapping

_NATIVE_BUSY = {
    "native rejected: complete stream already locked",
    "native rejected: BFT signer is already locked",
    "native rejected: file is already locked",
    "native rejected: Resource temporarily unavailable (os error 35)",
}
_RETRY_EXACT = {
    "TCP peer refused custody; retain queued evidence",
    "timed out",
    "The read operation timed out",
}
_RETRY_PARTS = (
    "Connection reset by peer", "Broken pipe", "UNEXPECTED_EOF_WHILE_READING",
    "The handshake operation timed out", "TCP stream closed",
    "Connection refused", "[Errno 61]", "[Errno 35]", "lock contention",
    "already locked",
)


def error_disposition(error):
    """Classify old accepted retries; Native busy remains unknown, never valid."""
    if not isinstance(error, str):
        raise ValueError("malformed runtime diagnostic")
    if error in _NATIVE_BUSY:
        return "unknown"
    if error.startswith("native rejected:"):
        raise ValueError("Native diagnostic requires refusal")
    if error in _RETRY_EXACT or any(term in error for term in _RETRY_PARTS):
        return "transport_retry"
    raise ValueError("unexpected runtime diagnostic requires refusal")


def receiving_stop_ready(observations, export_id, source_height):
    """Permit requesting a stop; never pass a payment or adopt an observed head."""
    if not isinstance(observations, (list, tuple)) or len(observations) != 5:
        return False
    if type(source_height) is not int or source_height < 0:
        raise ValueError("invalid source height")
    if not isinstance(export_id, str) or len(export_id) != 64 or any(
            char not in "0123456789abcdef" for char in export_id):
        raise ValueError("invalid pinned export identity")
    known = True
    for index, observation in enumerate(observations):
        if not isinstance(observation, Mapping):
            known = False
            continue
        if observation.get("rejected"):
            raise ValueError("received Native envelope rejected")
        errors = observation.get("errors")
        if not isinstance(errors, list):
            raise ValueError("malformed runtime diagnostics")
        for error in errors:
            if error_disposition(error) == "unknown":
                known = False
        consensus = observation.get("consensus")
        if not isinstance(consensus, Mapping):
            known = False
            continue
        if (consensus.get("progress_observation_available", True) is False
                or type(consensus.get("height")) is not int
                or consensus.get("caller_head_pending") is not False):
            known = False
        if index == 0:
            if (consensus.get("height") != source_height
                    or consensus.get("autonomous_signing_enabled") is not False
                    or consensus.get("explicit_stop_height_reached") is not True):
                known = False
            continue
        native = observation.get("native_observation")
        contacts = native.get("contacts") if isinstance(native, Mapping) else None
        if observation.get("native_observation_available") is not True or not isinstance(contacts, list):
            known = False
            continue
        if not any(isinstance(contact, Mapping)
                   and contact.get("export") == export_id
                   and contact.get("import_accepted") is True
                   and contact.get("original_recipient_output_spendable_now") is True
                   and contact.get("quarantined") is False for contact in contacts):
            known = False
    return known
