"""One-use scheduling observation from a fully authenticated Native receive.

A witness never signs or initializes a ledger. Next signing still executes the
original fresh pinned Native checks and independent pending/head persistence.
"""
import interstellar_mesh as mesh
import interstellar_transfer as wire
MAX_BYTES=8*1024*1024
# Unadopted performance candidate; explicit bounded controllers opt in.
CANDIDATE_ENABLED=False

def enabled(runtime):
    from regional_bft_node import ORIGIN_RUNTIME_FORMAT
    head=getattr(runtime,'head',None)
    return (CANDIDATE_ENABLED and getattr(runtime,'format',None)==ORIGIN_RUNTIME_FORMAT
        and getattr(runtime,'joint',None) is None
        and getattr(runtime,'_receive_phase_operation',None) is not None
        and type(head) is dict and head.get('head') is not None
        and head.get('pending') is None and head.get('outbox') is None)

def scope(runtime):
    return wire.canonical(dict(format=runtime.format,binding=runtime.signing_binding,
        head=runtime.head,signer=str(runtime.signer),key=runtime.key,region=runtime.region,
        native=[runtime.native.currency,runtime.native.authority,str(runtime.native.ledger)]))

def capture(runtime,value):
    runtime._received_phase_observation=None
    mesh.require(enabled(runtime),'receive phase lacks current reconciled unit')
    raw=wire.canonical(value)
    mesh.require(len(raw)<=MAX_BYTES and type(value) is dict and set(value)=={
        'format','native','signer','native_history_head','signing_authority','independent_freshness_qualified'}
        and value['format']=='RLD-BFT-LOOP-ORIGIN-OBSERVATION-V2'
        and value['signing_authority'] is False and value['independent_freshness_qualified'] is False,
        'receive phase observation domain differs')
    mesh.hex32(value['native_history_head'])
    mesh.require(value['signer']['binding']==runtime.signing_binding
        and value['signer']['head']==runtime.head['head'],'receive phase separate caller differs')
    bound=scope(runtime);mesh.require(len(bound)<=MAX_BYTES,'receive phase scope exceeds bound')
    runtime._received_phase_observation=(runtime._receive_phase_operation,bound,raw)

def take(runtime):
    observed=getattr(runtime,'_received_phase_observation',None)
    runtime._received_phase_observation=None
    if (observed is None or not enabled(runtime)
            or observed[0] is not runtime._receive_phase_operation or observed[1]!=scope(runtime)):
        return None
    return wire.decode_json(observed[2])
