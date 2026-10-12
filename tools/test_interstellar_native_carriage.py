"""Original first-carriage algorithm and callback order remain independent oracles."""
import copy
import random
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import interstellar_carriage_native as native
import interstellar_carriage_reference as reference
import interstellar_crypto as crypto
import interstellar_mesh as mesh
from test_interstellar_mesh import Fixture,NETWORK
from test_interstellar_native_routing import ident

PEER=ident(9000)
def candidate(active,receipts=(),recent=(),first=(),value=None):
    return SimpleNamespace(network=NETWORK,id=ident(9001),state=dict(messages={ident(i):{'ident':ident(i),'hops':[]} for i in active},
        receipts={ident(i):{} for i in receipts},recent_transits=[ident(i) for i in recent],first_arrivals=[ident(i) for i in first],
        first_carriage={PEER:mesh.empty_first_carriage() if value is None else value}))

class CarriageTests(unittest.TestCase):
    def compare(self,node,policy):
        before=copy.deepcopy(node.state);trace=[];calls={}
        def allowed(i):
            calls[i]=calls.get(i,0)+1;v=policy(i,calls[i]);trace.append((i,v));return v
        def transit(t,*args,**kwargs):return {'destination':t['ident'],'hop_limit':16},b'',[]
        node.route=lambda destination,*a,**k:[node.id,PEER] if allowed(destination) else None
        with patch.object(reference,'transit_check',side_effect=transit):old=reference.first_carriage_plan(node,PEER)
        original_trace=trace[:];trace.clear();calls.clear()
        raw=native._encode(node,PEER,256,32);result,observed=native._invoke(raw,allowed)
        self.assertEqual(result['plan'],old);self.assertEqual(trace,original_trace);self.assertEqual(observed,trace)
        self.assertEqual(node.state,before)
        trace.clear();calls.clear()
        with patch.object(mesh,'transit_check',side_effect=transit):actual=native.first_carriage_plan(node,PEER)
        self.assertEqual(actual,old);self.assertEqual(trace,original_trace);self.assertEqual(node.state,before)
    def test_initial_recent32_and_full_active256_retained_order(self):
        node=candidate(range(256),[2,4],range(40,72),range(256));self.compare(node,lambda i,n:int(i,16)%3!=0)
        value=mesh.empty_first_carriage();value.update(observed=[],prepared=[ident(10)],pending=[ident(1)],arrivals=[ident(4),ident(2)],history_after=ident(254),next_kind=1)
        self.compare(candidate(range(256),[3],range(32),range(255,-1,-1),value),lambda i,n:int(i,16)%5!=0)
    def test_original_laziness_rechecks_and_rotating_history_all_small_masks(self):
        for mask in range(16):
            for after in (None,ident(0),ident(3),ident(9)):
                for kind in (0,1):
                    for observed in (None,[],[ident(0)]):
                        v=mesh.empty_first_carriage();v.update(observed=observed,pending=[ident(1)],prepared=[ident(2)],arrivals=[ident(3)],history_after=after,next_kind=kind)
                        self.compare(candidate(range(4),[],[3,0,1],[3,1,0,2],v),lambda i,n:bool(mask&(1<<int(i,16))))
        v=mesh.empty_first_carriage();v.update(observed=[],arrivals=[ident(0),ident(1)])
        self.compare(candidate(range(4),[],[],range(4),v),lambda i,n:n%2==1)
    def test_missing_receipted_prepared_and_randomized_exact_order(self):
        rng=random.Random(31012)
        for _ in range(150):
            count=rng.randrange(1,70);ids=list(range(count));rng.shuffle(ids);spare=list(range(count,count+5));all_ids=ids+spare;rng.shuffle(all_ids)
            prepared=all_ids[:5];pending=all_ids[5:12];arrivals=all_ids[12:32]
            v=dict(prepared=[ident(i) for i in prepared],pending=[ident(i) for i in pending],arrivals=[ident(i) for i in arrivals],
                observed=None if rng.randrange(3)==0 else [ident(i) for i in all_ids[::2]],history_after=ident(rng.randrange(count+10)),next_kind=rng.randrange(2))
            self.compare(candidate(ids,ids[::7],ids[-32:],ids,v),lambda i,n:int(i,16)%3!=1)
    def test_malformed_partial_extra_capacity_and_null_callback_refuse_before_checks(self):
        node=candidate([0,1],[],[1],[0,1]);raw=native._encode(node,PEER,256,32);seen=[]
        for end in range(len(raw)):
            with self.assertRaises(ValueError):native._invoke(raw[:end],lambda i:seen.append(i) or True)
        for changed in (raw+b'x',b'bad'+raw,native.CODEC+b'\x01\x01'+raw[len(native.CODEC)+2:]):
            with self.assertRaises(ValueError):native._invoke(changed,lambda i:seen.append(i) or True)
        self.assertEqual(seen,[])
        for changed in (dict(node.state['first_carriage'][PEER],next_kind=True),dict(node.state['first_carriage'][PEER],pending=[ident(0)]*2)):
            node.state['first_carriage'][PEER]=changed
            with self.assertRaises(ValueError):native._encode(node,PEER,256,32)
        engine=crypto.backend();operation=engine.library.rld_contact_first_carriage
        # Explicit ABI refusal also retains its bounded common response/free contract.
        import interstellar_transfer as wire
        operation.argtypes=[crypto.ctypes.POINTER(crypto.ctypes.c_ubyte),crypto.ctypes.c_size_t,crypto.ctypes.c_void_p,crypto.ctypes.c_void_p]
        memory=(crypto.ctypes.c_ubyte*len(raw)).from_buffer_copy(raw);output=operation(memory,len(raw),None,None)
        try:reply=wire.decode_json(crypto.ctypes.string_at(output.data,output.len))
        finally:engine.library.rld_contact_crypto_free(output)
        self.assertIs(reply['success'],False);self.assertEqual(reply['error'],'missing carriage eligibility callback')
    def test_callback_original_exception_boolean_provider_transcript_and_reentrant_binding(self):
        raw=native._encode(candidate([0,1],[],[],[0,1]),PEER,256,32);engine=crypto.backend()
        def reentrant(i):self.assertEqual(engine.call('Info')['mesh'],mesh.VERSION);return True
        result,observed=native._invoke(raw,reentrant);self.assertEqual(len(result['plan']['pending']),2)
        for exc in (OSError('original native IO refusal'),ValueError('original proof refusal')):
            def refused(i):raise exc
            with self.assertRaises(type(exc)) as context:native._invoke(raw,refused)
            self.assertIs(context.exception,exc)
        with self.assertRaisesRegex(ValueError,'boolean'):native._invoke(raw,lambda i:1)
        call=engine.invoke_raw
        for field,value in [('eligibility_count',True),('eligibility_sha256','0'*64),('candidate_only',1),('ledger_authority',0),('custody_acknowledgment',0)]:
            def forged(operation,raw,*args):
                result=call(operation,raw,*args)
                if raw.startswith(native.CODEC):result=dict(result);result[field]=value
                return result
            with patch.object(engine,'invoke_raw',side_effect=forged),self.assertRaises(ValueError):native._invoke(raw,lambda i:True)
        # Change persists through the after-callback check, without replacing
        # the actual native function or granting an unchecked success.
        domain=crypto.validation_domain();calls=[0]
        def domain_switch():
            calls[0]+=1
            return domain if calls[0]<=2 else ('changed',)
        with patch.object(crypto,'validation_domain',side_effect=domain_switch),self.assertRaisesRegex(ValueError,'provider'):
            native._invoke(raw,lambda i:True)
        self.assertEqual(native._invoke(raw,lambda i:True)[0]['plan']['observed'],[ident(0),ident(1)])
    def test_typed_role_and_nested_result_forgeries_refuse_as_value_errors(self):
        node=candidate([0,1],[],[1],[0,1]);engine=crypto.backend();call=engine.invoke_raw
        def transit(t,*args,**kwargs):return {'destination':t['ident'],'hop_limit':16},b'',[]
        node.route=lambda *args,**kwargs:[node.id,PEER]
        for field,value in [('network',ident(99)),('peer',ident(99)),('node',ident(99)),
                ('plan',dict(mesh.empty_first_carriage(),observed=[ident(0),ident(1)],pending=[{}]))]:
            def forged(operation,raw,*args):
                result=call(operation,raw,*args)
                if raw.startswith(native.CODEC):result=copy.deepcopy(result);result[field]=value
                return result
            with patch.object(engine,'invoke_raw',side_effect=forged),patch.object(mesh,'transit_check',side_effect=transit),self.assertRaises(ValueError):
                native.first_carriage_plan(node,PEER)
        node.state['first_carriage'][PEER]['pending']=[{}]
        with self.assertRaises(ValueError):native._encode(node,PEER,256,32)
    def test_actual_complete_signed_transits_match_without_state_or_disk_mutation(self):
        with tempfile.TemporaryDirectory(prefix='rld-native-carriage-') as temporary:
            f=Fixture(temporary);f.rounds()
            with f.node('earth') as node:
                node.enqueue_batch([(f.frame(),f.identities['andromeda']['node_id'])]*4)
                for peer in node.contacts:
                    before=copy.deepcopy(node.state);disk=node.path.read_bytes()
                    self.assertEqual(native.first_carriage_plan(node,peer),reference.first_carriage_plan(node,peer))
                    self.assertEqual(node.state,before);self.assertEqual(node.path.read_bytes(),disk)
                    with patch.object(reference,'first_carriage_plan',side_effect=AssertionError('Python planner fallback')):
                        self.assertEqual(node.first_carriage_plan(peer),native.first_carriage_plan(node,peer))

if __name__=='__main__':unittest.main()
