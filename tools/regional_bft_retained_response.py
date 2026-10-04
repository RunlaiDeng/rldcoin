"""Startup carriage reuse after full cold checks and actual Native journal reads.

Exact response bytes choose only already authenticated retained envelopes.
This never recovers, signs, syncs, prunes, adopts heads or initializes a ledger.
"""
import hashlib
from types import MappingProxyType

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_retention import Messages

MAX_INDEX_BYTES=128*1024
MAX_MESSAGES=512
KINDS=('Proposal','Vote','Timeout')


def _response_id(raw):return hashlib.sha256(raw).hexdigest()


class RetainedResponses:
    def __init__(self,runtime,signed_body):
        self.runtime=runtime;self.signed_body=signed_body
        self.source=None;self.scope=None;self.index=None;self.limits=None

    def reuse(self,message):
        r=self.runtime
        mesh.require(getattr(r,'_retained_native_authenticated',False) is True,
                     'retained response reuse requires complete Native cold authentication')
        if type(message) is not dict or set(message).isdisjoint(KINDS):return False
        messages=r.state['messages']
        if not isinstance(messages,Messages) or len(messages)>MAX_MESSAGES:return False
        scope=wire.canonical(dict(binding=r.state['binding'],currency=r.native.currency,
                                  authority=r.native.authority,ledger=str(r.native.ledger),region=r.region))
        limits=(MAX_INDEX_BYTES,MAX_MESSAGES)
        if self.source is not messages or self.scope!=scope or self.limits!=limits:
            rows={}
            for ident,body,_,_ in messages.bodies():
                signed=self.signed_body(body)
                if type(signed) is dict and not set(signed).isdisjoint(KINDS):
                    raw=wire.canonical(signed)
                    rows.setdefault(_response_id(raw),[]).append(ident)
            self.source=messages;self.scope=scope;self.limits=limits
            self.index=(MappingProxyType({k:tuple(v) for k,v in rows.items()})
                        if len(wire.canonical(rows))<=MAX_INDEX_BYTES else None)
        if self.index is None:return False
        raw=wire.canonical(message)
        candidate=None
        for ident in self.index.get(_response_id(raw),()):
            record=messages.record(ident)
            # The digest is a hint only: compare the whole actual Native response.
            if wire.canonical(self.signed_body(record['body']))!=raw:continue
            if record['local']:return True
            if candidate is None:candidate=ident
        if candidate is None:return False
        r.save(dict(r.state,messages=messages.with_local(candidate)))
        return True
