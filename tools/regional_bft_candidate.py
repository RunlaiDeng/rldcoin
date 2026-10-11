"""Bounded transport for Native ordered candidate selection; no Python trials."""
import hashlib
import os
import tempfile

import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_submission_delivery_trace import candidate_event

FORMAT='RLD-NATIVE-BFT-CANDIDATE-SELECTION-V1'
MAX_BYTES=8*1024*1024
BATCH=16
SLOTS=4


def select(runtime,context,incoming):
    selected=[];seen=[];position=0
    while position<len(incoming) and len(selected)<SLOTS:
        batch=[]
        while position+len(batch)<len(incoming) and len(batch)<BATCH:
            proposed=batch+[incoming[position+len(batch)]]
            value=dict(context=context,selected=selected,seen=seen,commands=proposed)
            if len(wire.canonical(value))>MAX_BYTES:break
            batch=proposed
        mesh.require(batch,'candidate selection request capacity; retain all submissions')
        value=dict(context=context,selected=selected,seen=seen,commands=batch)
        raw=wire.canonical(value)
        result=runtime.with_json('bft-candidate-select',value,'--miner',runtime.miner)
        fields={'format','context','request_sha256','seen','attempts','selected_count','ledger_changed','signing_authority'}
        mesh.require(type(result) is dict and set(result)==fields and result['format']==FORMAT
            and result['context']==context and result['request_sha256']==hashlib.sha256(raw).hexdigest()
            and result['ledger_changed'] is False and result['signing_authority'] is False,
            'candidate selection Native binding differs')
        attempts=result['attempts'];returned_seen=result['seen']
        mesh.require(type(attempts) is list and len(attempts)<=len(batch)
            and type(returned_seen) is list and returned_seen==sorted(set(returned_seen)),
            'candidate selection response shape differs')
        newly_seen=[];additions=[];previous=-1
        for attempt in attempts:
            mesh.require(type(attempt) is dict and set(attempt)=={'index','command_id','selected'}
                and type(attempt['index']) is int and previous<attempt['index']<len(batch)
                and type(attempt['selected']) is bool,
                'candidate selection ordered attempt differs')
            index=attempt['index'];previous=index;command=batch[index]
            mesh.require(attempt['command_id']==mesh.digest(command)
                and attempt['command_id'] not in seen+newly_seen,
                'candidate selection command binding differs')
            newly_seen.append(attempt['command_id'])
            if attempt['selected']:additions.append(command)
        mesh.require(returned_seen==sorted(seen+newly_seen)
            and type(result['selected_count']) is int
            and result['selected_count']==len(selected)+len(additions)<=SLOTS,
            'candidate selection prefix or seen set differs')
        # These mark observation of Native's completed trial, not the beginning
        # of an individual command trial or a replacement payment clock.
        for attempt in attempts:
            command=batch[attempt['index']]
            candidate_event(runtime,'candidate_command_attempted',context,command=command)
            candidate_event(runtime,'candidate_command_selected' if attempt['selected'] else
                            'candidate_command_refused',context,command=command)
        selected.extend(additions);seen=returned_seen;position+=len(batch)
    # No serialized cursor/ledger survives this operation. The final native
    # call must freshly replay and match the same complete observed context.
    with tempfile.NamedTemporaryFile(dir=runtime.root,prefix='.native-candidate-context-',suffix='.json') as handle:
        handle.write(wire.canonical(context));handle.flush();os.fsync(handle.fileno())
        return runtime.with_json('bft-candidate',selected,'--miner',runtime.miner,'--context',handle.name)
