"""Bounded process-local signed-body lookup; never native authorization.

Only Runtime's already checked immutable message source uses this witness.
Every selected proposal/vote/certificate still takes the ordinary native path.
Store canonical bytes, not a mutable decoded payload or a native ledger.
"""
from dataclasses import dataclass
from types import MappingProxyType

import interstellar_transfer as wire
from regional_bft_retention import Messages

MAX_QUERY_BYTES = 8 * 1024 * 1024
MAX_QUERY_MESSAGES = 512
KINDS = ('Proposal', 'Vote', 'Timeout')


@dataclass(frozen=True)
class SignedQueryIndex:
    messages: object
    records: object
    snapshots: object
    context: bytes
    scope: bytes
    limits: tuple
    groups: object
    retained_bytes: int


def matching_context(kind, payload, context):
    if kind != 'Proposal':
        return payload.get('context') == context
    s = payload['snapshot']['statement']
    return (s['currency'] == context['currency'] and s['region'] == context['region']
            and s['epoch'] == context['epoch'] and s['previous'] == context['previous']
            and s['height'] == context['parent_height'] + 1)


def lookup(previous, messages, context, scope, round_number, kind, phase, value, signed_body):
    """Return (witness, fresh decoded rows), or None rows for the full scan.

    The refused marker also binds the exact source/context/limits, preventing
    repeated oversized builds. It retains no partial lookup that could hide a
    row. Source replacement, binding change and tightened limits build anew.
    """
    if (kind not in KINDS or not isinstance(messages, Messages)
            or type(messages._records) is not MappingProxyType
            or type(messages._snapshots) is not MappingProxyType):
        return None, None
    context_bytes, scope_bytes = wire.canonical(context), wire.canonical(scope)
    limits = (MAX_QUERY_BYTES, MAX_QUERY_MESSAGES)
    same = (isinstance(previous, SignedQueryIndex) and previous.messages is messages
            and previous.records is messages._records and previous.snapshots is messages._snapshots
            and previous.context == context_bytes and previous.scope == scope_bytes
            and previous.limits == limits)
    if not same:
        groups = {}
        retained = len(context_bytes) + len(scope_bytes)
        refused = len(messages) > MAX_QUERY_MESSAGES or retained > MAX_QUERY_BYTES
        if not refused:
            for _, body, message_value, _ in messages.bodies():
                message = signed_body(body)
                k = next((k for k in KINDS if k in message), None)
                if k is None:
                    continue
                payload = message[k]
                if not matching_context(k, payload, context):
                    continue
                encoded = wire.canonical(payload)
                metadata = (k, payload['round'], payload.get('phase'), message_value)
                retained += len(encoded) + len(wire.canonical(metadata))
                if retained > MAX_QUERY_BYTES:
                    refused = True
                    break
                groups.setdefault((k, payload['round']), []).append(
                    (encoded, message_value, payload.get('phase')))
        previous = SignedQueryIndex(messages, messages._records, messages._snapshots,
                                    context_bytes, scope_bytes, limits,
                                    None if refused else MappingProxyType({k: tuple(v) for k, v in groups.items()}),
                                    0 if refused else retained)
    if previous.groups is None:
        return previous, None
    rows = previous.groups.get((kind, round_number), ())
    return previous, [(wire.decode_json(raw), message_value)
                      for raw, message_value, recorded_phase in rows
                      if (phase is None or recorded_phase == phase)
                      and (value is None or message_value == value)]
