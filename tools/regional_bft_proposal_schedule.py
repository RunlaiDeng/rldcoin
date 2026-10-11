"""Typed bridge to Native proposal opportunity; no policy or failure fallback."""
import interstellar_mesh as mesh

FORMAT='RLD-NATIVE-BFT-PROPOSAL-OPPORTUNITY-V1'

def opportunity(runtime,context,round_number):
    result=runtime.with_json('bft-proposal-opportunity',context,
        '--signer-dir',runtime.signer,'--expected-head',runtime.head['head'],
        '--state-dir',runtime.root,'--expected-state-sha256',runtime._archive_head,
        '--expected-key',runtime.key,'--runtime-format',runtime.format,'--round',str(round_number))
    fields={'format','context','round','key','caller_head','archive_sha256',
        'authenticated_messages','current_proposals','future_proposals','proposed_round',
        'leader','timeout','high','can_propose','ledger_changed','signing_authority',
        'independent_freshness_qualified'}
    mesh.require(type(result) is dict and set(result)==fields and result['format']==FORMAT
        and result['context']==context and type(result['round']) is int and result['round']==round_number
        and result['key']==runtime.key and result['caller_head']==runtime.head['head']
        and result['archive_sha256']==runtime._archive_head
        and type(result['authenticated_messages']) is int
        and 0<=result['authenticated_messages']<=len(runtime.state['messages'])
        and type(result['proposed_round']) is int and round_number<=result['proposed_round']<32
        and result['leader'] in runtime.peers
        and all(type(result[k]) is bool for k in ('current_proposals','future_proposals','can_propose'))
        and result['ledger_changed'] is False and result['signing_authority'] is False
        and result['independent_freshness_qualified'] is False,
        'Native BFT proposal opportunity binding differs')
    if result['high'] is not None:mesh.hex32(result['high'])
    mesh.require((result['timeout'] is None or type(result['timeout']) is dict)
        and (result['proposed_round']!=0 or result['timeout'] is None)
        and (result['timeout'] is not None or result['high'] is None),
        'Native BFT proposal opportunity certificate shape differs')
    return result
