"""Complete ground carriage adversaries; no ledger/value/signing qualification."""
import base64
import copy
import hashlib
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_transfer as wire
import interstellar_transit_native as native
import interstellar_transit_reference as reference
from interstellar_crypto import backend
from test_interstellar_mesh import Fixture,NETWORK

class TransitTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-native-transit-');self.addCleanup(temporary.cleanup)
        self.f=Fixture(temporary.name);self.nodes=[self.f.node(n) for n in self.f.names]
        for n in self.nodes:self.addCleanup(n.close)
        self.source,self.relay,self.destination=self.nodes
    def body(self,node):return dict(format=mesh.VERSION,network=NETWORK,node_id=node.id)
    def sign(self,node,kind,body):return mesh.sign(node.key,kind,body)
    def packet(self,raw=None,**changes):
        body=dict(self.body(self.source),destination=self.destination.id,nonce='9'*64,hop_limit=16,
                  frame=base64.b64encode(raw if raw is not None else self.f.frame()).decode())
        body.update(changes);return self.sign(self.source,'packet',body)
    def route(self,packet,**changes):
        raw=base64.b64decode(packet['body']['frame']);frame=wire.decode_json(raw)
        body=dict(self.body(self.source),packet_id=reference.digest(packet),destination=packet['body']['destination'],frame_id=frame['message_id'])
        body.update(changes);return self.sign(self.source,'receipt-route',body)
    def hop(self,node,packet,previous,to,**changes):
        body=dict(self.body(node),packet_id=reference.digest(packet),previous=previous,to=to)
        body.update(changes);return self.sign(node,'hop',body)
    def transit(self,count=2,**changes):
        packet=self.packet(**changes);route=self.route(packet);hops=[];previous=reference.digest(packet)
        for node,to in [(self.source,self.relay.id),(self.relay,self.destination.id)][:count]:
            h=self.hop(node,packet,previous,to);hops.append(h);previous=reference.digest(h)
        return dict(packet=packet,routing=route,hops=hops)
    def compare(self,value,accepted=True,recipient=None,sender=None):
        functions=(lambda:reference._transit_check(value,NETWORK,recipient,sender),lambda:native.transit(value,NETWORK,recipient,sender))
        if accepted:self.assertEqual(functions[0](),functions[1]())
        else:
            for check in functions:
                with self.assertRaises(ValueError):check()
    def test_valid_zero_one_two_hops_exact_packet_frame_and_contact_binding(self):
        for count in range(3):
            value=self.transit(count);before=copy.deepcopy(value);self.compare(value)
            self.assertEqual(reference._packet_frame_check(value['packet'],NETWORK),native.packet(value['packet'],NETWORK))
            self.assertEqual(mesh.packet_check(value['packet'],NETWORK),reference.packet_check(value['packet'],NETWORK))
            self.assertEqual(value,before)
        self.compare(self.transit(),recipient=self.destination.id,sender=self.relay.id)
        self.compare(self.transit(1),recipient=self.relay.id,sender=self.source.id)
    def test_resigned_packet_fields_types_bounds_and_complete_frame_rejections(self):
        valid=self.packet();self.assertEqual(reference._packet_frame_check(valid,NETWORK),native.packet(valid,NETWORK))
        changes=[dict(destination='bad'),dict(nonce='A'*64),dict(extra=None)]
        changes += [dict(hop_limit=x) for x in (0,17,True,1.0,-1)]
        changes += [dict(frame=x) for x in (None,'!','A','AAAA','',valid['body']['frame']+'=')]
        for change in changes:
            value=self.packet(**change)
            for check in (lambda:reference._packet_frame_check(value,NETWORK),lambda:native.packet(value,NETWORK)):
                with self.assertRaises(ValueError):check()
        frame=wire.decode_json(self.f.frame())
        for field,value in [('message_id','0'*64),('payload_sha256','0'*64),('source_chain_id','A'*64),('extra',None)]:
            bad=dict(frame);bad[field]=value;packet=self.packet(wire.canonical(bad))
            for check in (lambda:reference._packet_frame_check(packet,NETWORK),lambda:native.packet(packet,NETWORK)):
                with self.assertRaises(ValueError):check()
        packet=self.packet(self.f.frame()+b' ')
        for check in (lambda:reference._packet_frame_check(packet,NETWORK),lambda:native.packet(packet,NETWORK)):
            with self.assertRaises(ValueError):check()
    def test_source_route_must_match_whole_signed_packet_and_verified_frame(self):
        value=self.transit()
        for field,changed in [('packet_id','0'*64),('destination',self.relay.id),('frame_id','0'*64)]:
            bad=copy.deepcopy(value);bad['routing']=self.route(bad['packet'],**{field:changed});self.compare(bad,False)
        bad=copy.deepcopy(value);body=dict(bad['routing']['body'],node_id=self.relay.id)
        bad['routing']=self.sign(self.relay,'receipt-route',body);self.compare(bad,False)
        bad=copy.deepcopy(value);bad['packet']=self.packet(nonce='8'*64);self.compare(bad,False)
    def test_every_complete_packet_route_hop_signature_and_domain_authenticates(self):
        value=self.transit();self.compare(value)
        for part in ('packet','routing','hop0','hop1'):
            for field,changed in [('signature','0'*128),('public_key','0'*64),('extra',None)]:
                bad=copy.deepcopy(value);signed=bad['hops'][int(part[-1])] if part.startswith('hop') else bad[part]
                signed[field]=changed;self.compare(bad,False)
        bad=copy.deepcopy(value);bad['hops'][0]=self.sign(self.source,'receipt-route',bad['hops'][0]['body']);self.compare(bad,False)
        with self.assertRaises(ValueError):native.transit(value,'f'*64)
    def test_resigned_broken_previous_packet_signer_loop_and_hop_fields_refuse(self):
        value=self.transit()
        for changes in [dict(previous='0'*64),dict(packet_id='0'*64),dict(to='bad'),dict(to=self.source.id),dict(extra=0)]:
            bad=copy.deepcopy(value);bad['hops'][1]=self.hop(self.relay,bad['packet'],changes.get('previous',reference.digest(bad['hops'][0])),changes.get('to',self.destination.id),**{k:v for k,v in changes.items() if k not in ('to','previous')});self.compare(bad,False)
        bad=copy.deepcopy(value);bad['hops'][1]=self.hop(self.destination,bad['packet'],reference.digest(bad['hops'][0]),self.destination.id);self.compare(bad,False)
        bad=self.transit(hop_limit=1);self.compare(bad,False)
        for hops in (None,{},['bad']):
            bad=copy.deepcopy(value);bad['hops']=hops;self.compare(bad,False)
        bad=dict(value,extra=0);self.compare(bad,False)
    def test_exact_contact_last_signer_and_hop_required_only_when_recipient_supplied(self):
        for count,recipient,sender in [(0,self.source.id,None),(2,self.relay.id,self.relay.id),
                (2,self.destination.id,self.source.id),(2,self.destination.id,None)]:
            self.compare(self.transit(count),False,recipient,sender)
        self.compare(self.transit(0),sender=False)
    def test_regional_currency_binding_remains_separate_from_native_value_authentication(self):
        for currency in (NETWORK,'f'*64):
            payload=wire.canonical(dict(format='RLD-REGIONAL-BFT-NETWORK-V2',currency=currency,region='1'*64,evidence=[],body={}))
            raw=wire.make_frame('regional-bft','1'*64,'1'*64,hashlib.sha256(payload).hexdigest(),payload)
            packet=self.packet(raw)
            if currency==NETWORK:self.assertEqual(reference._packet_frame_check(packet,NETWORK),native.packet(packet,NETWORK))
            else:
                for check in (lambda:reference._packet_frame_check(packet,NETWORK),lambda:native.packet(packet,NETWORK)):
                    with self.assertRaises(ValueError):check()
    def test_smaller_hop_frame_and_payload_limits_preserve_independent_refusal(self):
        value=self.transit()
        for module,name,limit in [(mesh,'MAX_HOPS',1),(wire,'MAX_FRAME',1),(wire,'MAX_PAYLOAD',1)]:
            with patch.object(module,name,limit),self.assertRaises(ValueError):native.transit(value,NETWORK)
            ref=reference if name=='MAX_HOPS' else reference.evidence
            with patch.object(ref,name,limit),self.assertRaises(ValueError):reference._transit_check(value,NETWORK)
    def test_default_full_check_has_no_python_signature_frame_or_route_fallback(self):
        value=self.transit();expected=reference._transit_check(value,NETWORK)
        with (patch.object(mesh,'verify',side_effect=AssertionError('Python verify dispatch')),
              patch.object(mesh,'receipt_route_check',side_effect=AssertionError('Python route dispatch')),
              patch.object(wire,'inspect_frame',side_effect=AssertionError('Python frame dispatch'))):
            self.assertEqual(mesh._transit_check(value,NETWORK),expected)
    def test_sixteen_distinct_signed_hops_and_one_over_bound(self):
        nodes=[self.source]
        for _ in range(16):
            key=mesh.Ed25519PrivateKey.generate()
            public=key.public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex()
            nodes.append(SimpleNamespace(key=key,id=mesh.node_id(public)))
        packet=self.packet(destination=nodes[-1].id);value=dict(packet=packet,routing=self.route(packet),hops=[])
        previous=reference.digest(packet)
        for node,following in zip(nodes,nodes[1:]):
            hop=self.hop(node,packet,previous,following.id);value['hops'].append(hop);previous=reference.digest(hop)
        self.compare(value,recipient=nodes[-1].id,sender=nodes[-2].id)
        value['hops'].append(copy.deepcopy(value['hops'][-1]));self.compare(value,False)
    def test_response_complete_body_frame_path_and_literal_authority_bindings(self):
        value=self.transit();engine=backend();call=engine.call
        for name,changed in [('ledger_authority',0),('transport_authenticated',1),('body',{}),('frame',{}),('visited',[])]:
            def forged(request):
                result=call(request)
                if type(request) is dict and 'Transit' in request:
                    result=dict(result);result[name]=changed
                return result
            with patch.object(engine,'call',side_effect=forged),self.assertRaises(ValueError):native.transit(value,NETWORK)

if __name__=='__main__':unittest.main()
