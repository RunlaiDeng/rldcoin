"""Pure candidate BFS against the original Python oracle and actual mesh inputs."""
import copy
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_routing_native as native
import interstellar_routing_reference as reference
import interstellar_crypto as crypto
import interstellar_transfer as wire
from test_interstellar_mesh import Fixture,NETWORK

def ident(n):return f'{n:064x}'
def candidate(graph,contacts,source=0):
    return SimpleNamespace(network=NETWORK,id=ident(source),state={'adverts':{ident(k):{'body':{'neighbors':[ident(v) for v in peers]}} for k,peers in graph.items()}},contacts={ident(k):v for k,v in contacts.items()})

class RoutingTests(unittest.TestCase):
    def compare(self,node,destination,excluded=(),first=None):
        before=copy.deepcopy((node.state,node.contacts))
        old=reference.route(node,destination,excluded,first);new=native.route(node,destination,excluded,first)
        self.assertEqual(old,new);self.assertEqual((node.state,node.contacts),before);return new
    def test_branch_order_shortest_path_ties_and_exact_configured_first_hop(self):
        node=candidate({0:[2,1],1:[3],2:[3],3:[]},{1:{'outbox':'configured'},2:{'host':'127.0.0.1'}})
        self.assertEqual(self.compare(node,ident(3)),[ident(0),ident(2),ident(3)])
        self.assertEqual(self.compare(node,ident(3),first=ident(1)),[ident(0),ident(1),ident(3)])
        self.assertIsNone(self.compare(node,ident(3),first=ident(4)))
        node.state['adverts'][ident(0)]['body']['neighbors']=[ident(1),ident(2)]
        self.assertEqual(self.compare(node,ident(3)),[ident(0),ident(1),ident(3)])
    def test_all_directed_three_node_graphs_and_contact_exclusion_choices(self):
        edges=[(a,b) for a in range(3) for b in range(3) if a!=b]
        for mask in range(1<<len(edges)):
            graph={n:[] for n in range(3)}
            for i,(a,b) in enumerate(edges):
                if mask&(1<<i):graph[a].append(b)
            node=candidate(graph,{1:{'outbox':'out'},2:{'outbox':'out'}})
            for destination in range(3):
                for excluded in ([],[ident(1)],[ident(2)],[ident(1),ident(2)]):
                    for first in (None,ident(1),ident(2)):
                        self.assertEqual(reference.route(node,ident(destination),excluded,first),native.route(node,ident(destination),excluded,first))
    def test_exclusions_cycles_unconfigured_and_incoming_only_first_hops(self):
        node=candidate({0:[1,2,4],1:[0,3],2:[1,3],3:[0]},{1:{'inbox':'only'},2:{'outbox':'out'},4:{'host':'127.0.0.1'}})
        self.assertEqual(self.compare(node,ident(3)),[ident(0),ident(2),ident(3)])
        self.assertIsNone(self.compare(node,ident(3),[ident(2)]))
        self.assertIsNone(self.compare(node,ident(3),first=ident(1)))
        self.assertIsNone(self.compare(node,ident(9)))
        node.contacts.pop(2,None);node.contacts.pop(ident(2))
        self.assertIsNone(self.compare(node,ident(3)))
    def test_self_destination_ignores_unused_graph_exclusions_and_first_hop(self):
        node=candidate({},{});node.state['adverts']=None
        self.assertEqual(self.compare(node,node.id,None,False),[node.id])
        with patch.object(mesh,'MAX_NODES',0),patch.object(mesh,'MAX_CONTACTS',0):
            self.assertEqual(native.route(node,node.id),[node.id])
    def test_missing_and_dangling_advertisements_and_directed_asymmetry(self):
        node=candidate({0:[1],1:[2]},{1:{'outbox':'out'}})
        self.assertEqual(self.compare(node,ident(2)),[ident(0),ident(1),ident(2)])
        self.assertIsNone(self.compare(node,ident(3)))
        node.state['adverts'][ident(1)]={}
        self.assertIsNone(self.compare(node,ident(2)))
        node.state['adverts']={}
        self.assertIsNone(self.compare(node,ident(1)))
    def test_candidate_path65_and1024_neighbor_edges_do_not_raise_packet_hops(self):
        graph={i:[i+1] for i in range(64)};node=candidate(graph,{1:{'outbox':'out'}})
        path=self.compare(node,ident(64));self.assertEqual(len(path),65);self.assertEqual(mesh.MAX_HOPS,16)
        graph={i:([i+1] if i<63 else [])+[1000+16*i+j for j in range(15 if i<63 else 16)] for i in range(64)}
        node=candidate(graph,{p:{'outbox':'out'} for p in graph[0]})
        self.assertEqual(sum(len(p) for p in graph.values()),1024)
        self.assertIsNone(self.compare(node,ident(999999)))
        self.assertEqual(len(self.compare(node,ident(graph[63][-1]))),65)
        self.compare(node,ident(999999),[ident(100000+i) for i in range(1025)])
    def test_caller_limits_and_malformed_typed_graph_refuse_without_cache(self):
        node=candidate({0:[1],1:[2]},{1:{'outbox':'out'}});self.compare(node,ident(2))
        for name,limit in [('MAX_NODES',1),('MAX_CONTACTS',0)]:
            with patch.object(mesh,name,limit),self.assertRaises(ValueError):native.route(node,ident(2))
        bad=copy.deepcopy(node);bad.state['adverts'][ident(1)]['body']['neighbors']=[ident(2)]*17
        with self.assertRaises(ValueError):native.route(bad,ident(2))
        bad=copy.deepcopy(node);bad.state['adverts'][ident(1)]['body']['neighbors']=['bad']
        with self.assertRaises(ValueError):native.route(bad,ident(2))
        with self.assertRaises(ValueError):native.route(node,'invalid')
    def test_actual_ordinary_mesh_route_uses_native_search_and_retains_signed_state(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-native-routing-');self.addCleanup(temporary.cleanup)
        f=Fixture(temporary.name);f.rounds()
        with f.node('earth') as node:
            destination=f.identities['andromeda']['node_id'];before=copy.deepcopy(node.state);disk=node.path.read_bytes()
            expected=reference.route(node,destination)
            with patch.object(reference,'route',side_effect=AssertionError('Python fallback')):
                self.assertEqual(node.route(destination),expected)
            self.assertEqual(node.state,before);self.assertEqual(node.path.read_bytes(),disk)
            for key,advert in node.state['adverts'].items():self.assertEqual(mesh.advert_check(advert,NETWORK)['node_id'],key)
    def test_result_role_edge_path_and_current_provider_binding(self):
        node=candidate({0:[1],1:[2]},{1:{'outbox':'out'}});engine=crypto.backend();call=engine.invoke_raw
        for field,changed in [('candidate_only',1),('labels_authenticated',0),('ledger_authority',0),('custody_acknowledgment',0),
                ('destination',ident(4)),('path',[ident(0),ident(2)]),('path',[ident(0),ident(1),ident(1),ident(2)])]:
            def forged(operation,raw,*args):
                result=call(operation,raw,*args)
                if raw.startswith(native.CODEC):result=dict(result);result[field]=changed
                return result
            with patch.object(engine,'invoke_raw',side_effect=forged),self.assertRaises(ValueError):native.route(node,ident(2))
        class Provider:
            library=engine.library
            def invoke_raw(self,*args):raise ValueError('MODEL_CHANGED_ROUTING_PROVIDER_REFUSES')
        with patch.object(crypto,'backend',return_value=Provider()),self.assertRaisesRegex(ValueError,'MODEL_CHANGED_ROUTING_PROVIDER_REFUSES'):
            native.route(node,ident(2))
    def test_actual_candidate_ascii_abi_keeps_python_bytes_and_noncanonical_refusal(self):
        engine=crypto.backend()
        request={'Routing':dict(network=NETWORK,node=ident(0),destination=ident(2),excluded=[],first_hop=None,
            outgoing=[ident(1)],graph={ident(0):[ident(1)],ident(1):[ident(2)]},limits=dict(nodes=64,contacts=16))}
        def invoke(raw):
            memory=(crypto.ctypes.c_ubyte*len(raw)).from_buffer_copy(raw)
            result=engine.library.rld_contact_crypto(memory,len(raw))
            try:return crypto.ctypes.string_at(result.data,result.len)
            finally:engine.library.rld_contact_crypto_free(result)
        raw=wire.canonical(request);output=invoke(raw);reply=wire.decode_json(output)
        self.assertIs(reply['success'],True);self.assertEqual(output,wire.canonical(reply))
        self.assertEqual(reply['value']['path'],[ident(0),ident(1),ident(2)])
        for changed in (raw+b' ',b' '+raw,raw.replace(b'"Routing":',b'"Routing" :',1)):
            result=wire.decode_json(invoke(changed));self.assertIs(result['success'],False)
            self.assertEqual(result['error'],'contact ABI noncanonical input')
    def test_candidate_byte_codec_matches_json_and_original_search_without_mutation(self):
        node=candidate({0:[2,1],1:[3],2:[3],3:[]},{1:{'outbox':'out'},2:{'outbox':'out'}})
        graph={key:value['body']['neighbors'] for key,value in node.state['adverts'].items()}
        outgoing=list(node.contacts)
        for excluded in ([],[ident(2)]):
            for first in (None,ident(1),ident(2)):
                raw=native._encode(NETWORK,node.id,ident(3),excluded,first,outgoing,graph,64,16)
                result=native._invoke(raw)
                json_result=crypto.backend().call({'Routing':dict(network=NETWORK,node=node.id,destination=ident(3),excluded=excluded,
                    first_hop=first,outgoing=outgoing,graph=graph,limits=dict(nodes=64,contacts=16))})
                self.assertEqual(result['path'],json_result['path']);self.assertEqual(result['path'],reference.route(node,ident(3),excluded,first))
                self.assertEqual(result['codec'],native.CODEC[:-1].decode())
                self.assertIs(result['labels_authenticated'],False);self.assertIs(result['ledger_authority'],False)
    def test_candidate_byte_partial_extra_mixed_version_flags_rows_and_capacity_refuse(self):
        graph={ident(0):[ident(1)],ident(1):[ident(2)]}
        raw=native._encode(NETWORK,ident(0),ident(2),[],None,[ident(1)],graph,64,16)
        for end in range(len(raw)):
            with self.assertRaises(ValueError):native._invoke(raw[:end])
        bad=bytearray(raw);bad[0]^=1
        with self.assertRaises(ValueError):native._invoke(bytes(bad))
        with self.assertRaises(ValueError):native._invoke(raw+b'x')
        prefix=len(native.CODEC)
        for offset,value in [(prefix,65),(prefix+1,17),(prefix+2+96,2)]:
            bad=bytearray(raw);bad[offset]=value
            with self.assertRaises(ValueError):native._invoke(bytes(bad))
        # No first hop/exclusions: one outgoing ID, then two complete graph rows.
        rows_start=prefix+2+96+1+2+1+32+1
        for altered in [raw[:rows_start]+raw[rows_start+65:]+raw[rows_start:rows_start+65],
                        raw[:rows_start+65]+raw[rows_start:rows_start+65]]:
            with self.assertRaises(ValueError):native._invoke(altered)
        with self.assertRaises(ValueError):native._invoke(b'x'*(native.MAX_BYTES+1))
    def test_whole_candidate_byte_request_hash_and_exact_free_survive_response_failure(self):
        engine=crypto.backend();operation=engine.library.rld_contact_routing_bytes
        operation.argtypes=[crypto.ctypes.POINTER(crypto.ctypes.c_ubyte),crypto.ctypes.c_size_t];operation.restype=crypto.Buffer
        raw=native._encode(NETWORK,ident(0),ident(1),[],None,[ident(1)],{ident(0):[ident(1)]},64,16)
        def changed_input(memory,size):
            changed=bytearray(crypto.ctypes.string_at(memory,size));changed[-1]^=1
            altered=(crypto.ctypes.c_ubyte*len(changed)).from_buffer_copy(changed)
            return operation(altered,len(changed))
        with self.assertRaisesRegex(ValueError,'receipt binding'):engine.invoke_raw(changed_input,raw)
        self.assertEqual(native._invoke(raw)['path'],[ident(0),ident(1)])

if __name__=='__main__':unittest.main()
