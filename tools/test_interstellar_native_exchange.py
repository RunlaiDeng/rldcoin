"""Independent re-signed ground control adversaries; no value/custody authority."""
import copy
import tempfile
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_exchange_native as native
import interstellar_exchange_reference as reference
import interstellar_crypto as crypto
from test_interstellar_mesh import Fixture,NETWORK

class ExchangeTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-native-exchange-');self.addCleanup(temporary.cleanup)
        self.f=Fixture(temporary.name);self.nodes=[self.f.node(n) for n in self.f.names]
        for n in self.nodes:self.addCleanup(n.close)
        self.source,self.destination,self.other=self.nodes
        self.pin='2'*64;self.nonce='3'*64;self.peers={self.source.id:{}}
    def body(self,node):return dict(format=mesh.VERSION,network=NETWORK,node_id=node.id)
    def sign(self,node,kind,body):return mesh.sign(node.key,kind,body)
    def bundle(self,node=None,to=None,**changes):
        node=node or self.source;to=to or self.destination.id
        inventory=self.sign(node,'inventory',dict(self.body(node),packet_ids=[]))
        body=dict(self.body(node),to=to,adverts=[],transits=[],receipts=[],inventory=inventory)
        body.update(changes);return self.sign(node,'exchange',body)
    def hello(self,**changes):
        body=dict(self.body(self.destination),adapter=tcp.ADAPTER,nonce='4'*64,tls_cert_sha256=self.pin)
        body.update(changes);return self.sign(self.destination,'tcp-challenge',body)
    def request(self,**changes):
        body=dict(self.body(self.source),adapter=tcp.ADAPTER,to=self.destination.id,nonce='5'*64,
                  challenge=self.nonce,bundle=self.bundle())
        body.update(changes);return self.sign(self.source,'tcp-request',body)
    def response(self,sent=None,**changes):
        sent=sent or self.request()
        body=dict(self.body(self.destination),adapter=tcp.ADAPTER,to=self.source.id,
            nonce=sent['body']['nonce'],challenge=sent['body']['challenge'],exchange_id=reference.mesh.digest(sent['body']['bundle']),
            accepted=True,bundle=self.bundle(self.destination,self.source.id),error=None)
        body.update(changes);return self.sign(self.destination,'tcp-response',body)
    def compare(self,value,mode,accepted=True,**overrides):
        kwargs=dict(network=NETWORK)
        if mode=='exchange':kwargs=dict(bundle=value,peer=self.source.id)
        elif mode=='challenge':kwargs.update(value=value,peer=self.destination.id,fingerprint=self.pin)
        elif mode=='request':kwargs.update(value=value,recipient=self.destination.id,peers=self.peers,connection_nonce=self.nonce)
        else:kwargs.update(value=value,requester=self.source.id,peer=self.destination.id,sent=overrides.pop('sent',self.request()))
        kwargs.update(overrides)
        functions={'exchange':(lambda **x:reference.exchange_check(self.destination,**x),lambda **x:native.exchange_check(self.destination,**x)),'challenge':(reference.check_challenge,native.check_challenge),
            'request':(reference.check_request,native.check_request),'response':(reference.check_response,native.check_response)}[mode]
        if accepted:self.assertEqual(functions[0](**kwargs),functions[1](**kwargs))
        else:
            for check in functions:
                with self.assertRaises(ValueError):check(**kwargs)
    def test_valid_exact_outer_controls_and_explicit_insecure_challenge_binding(self):
        for mode,value in [('exchange',self.bundle()),('challenge',self.hello()),('request',self.request()),('response',self.response())]:
            before=copy.deepcopy(value);self.compare(value,mode);self.assertEqual(value,before)
        self.compare(self.hello(tls_cert_sha256=None),'challenge',fingerprint=None)
        self.assertEqual(tcp.check_challenge(self.hello(),NETWORK,self.destination.id,self.pin),'4'*64)
        self.assertEqual(tcp.check_request(self.request(),NETWORK,self.destination.id,self.peers,self.nonce),self.request()['body'])
        sent=self.request();reply=self.response(sent);self.assertEqual(tcp.check_response(reply,NETWORK,self.source.id,self.destination.id,sent),reply['body']['bundle'])
    def test_resigned_outer_exchange_peer_fields_inventory_and_item_limits(self):
        for changes in [dict(to=self.other.id),dict(extra=None),dict(adverts=None),dict(transits={}),dict(receipts=False),
                dict(adverts=[None]*65),dict(transits=[None]*5),dict(receipts=[None]*257)]:
            self.compare(self.bundle(**changes),'exchange',False)
        other=self.sign(self.other,'inventory',dict(self.body(self.other),packet_ids=[]))
        self.compare(self.bundle(inventory=other),'exchange',False)
        inventory=self.sign(self.source,'inventory',dict(self.body(self.source),packet_ids=['0'*64]*2))
        self.compare(self.bundle(inventory=inventory),'exchange',False)
        self.compare(self.bundle(adverts=[None]*64,transits=[None]*4,receipts=[None]*256),'exchange')
        self.compare(self.bundle(),'exchange',False,peer=self.other.id)
        with patch.object(self.destination,'contacts',{}):self.compare(self.bundle(),'exchange',False)
        contacts=copy.deepcopy(self.destination.contacts);contacts[self.source.id].pop('inbox')
        contacts[self.source.id]['adapter']=mesh.SPOOL_ONEWAY
        with patch.object(self.destination,'contacts',contacts):
            self.compare(self.bundle(),'exchange',False)
    def test_resigned_challenge_adapter_identity_nonce_and_independent_pin(self):
        for changes in [dict(adapter='RLD-CONTACT-TCP-V3'),dict(nonce='bad'),dict(nonce=True),dict(extra=0),dict(tls_cert_sha256='0'*64)]:
            self.compare(self.hello(**changes),'challenge',False)
        self.compare(self.hello(),'challenge',False,peer=self.other.id)
        self.compare(self.hello(),'challenge',False,fingerprint=None)
    def test_resigned_request_fresh_challenge_configured_peer_nonce_and_bundle_bindings(self):
        for changes in [dict(adapter='old'),dict(to=self.other.id),dict(challenge='0'*64),dict(nonce='bad'),dict(nonce=False),dict(extra=0),
                dict(bundle=self.bundle(to=self.other.id)),dict(bundle=self.bundle(self.other,self.destination.id))]:
            self.compare(self.request(**changes),'request',False)
        self.compare(self.request(),'request',False,peers={})
        self.compare(self.request(),'request',False,connection_nonce='0'*64)
        bundle=self.bundle();bundle['signature']='0'*128
        self.compare(self.request(bundle=bundle),'request',False)
        peers={f'{n:064x}':{} for n in range(15)};peers[self.source.id]={}
        self.compare(self.request(),'request',peers=peers)
        peers['f'*64]={}
        with self.assertRaises(ValueError):native.check_request(self.request(),NETWORK,self.destination.id,peers,self.nonce)
    def test_resigned_response_exact_original_exchange_both_nonces_and_peer_roles(self):
        sent=self.request();reply=self.response(sent)
        for field,value in [('adapter','old'),('to',self.other.id),('nonce','0'*64),('challenge','0'*64),('exchange_id','0'*64),('extra',None)]:
            self.compare(self.response(sent,**{field:value}),'response',False,sent=sent)
        self.compare(reply,'response',False,sent=self.request(nonce='0'*64))
        self.compare(reply,'response',False,sent=self.request(challenge='0'*64))
        self.compare(reply,'response',False,sent=self.request(bundle=self.bundle(adverts=[None])))
        self.compare(reply,'response',False,peer=self.other.id,sent=sent)
        self.compare(reply,'response',False,requester=self.other.id,sent=sent)
    def test_acknowledgment_literal_bool_and_refusal_success_shapes(self):
        for changes in [dict(accepted=x) for x in (0,1,None,'true')]:
            self.compare(self.response(**changes),'response',False)
        for changes in [dict(error='CONTACT_REJECTED'),dict(bundle=None),dict(bundle=[]),dict(bundle=self.bundle(to=self.other.id)),
                dict(bundle=self.bundle(self.other,self.source.id)),dict(accepted=False,bundle=None,error=None),
                dict(accepted=False,error='CONTACT_REJECTED'),dict(accepted=False,bundle=None,error='wrong')]:
            self.compare(self.response(**changes),'response',False)
        refusal=self.response(accepted=False,bundle=None,error='CONTACT_REJECTED')
        for check in (reference.check_response,native.check_response):
            with self.assertRaisesRegex(ValueError,'TCP peer refused custody; retain queued evidence'):
                check(refusal,NETWORK,self.source.id,self.destination.id,self.request())
        bundle=self.bundle(self.destination,self.source.id);bundle['signature']='0'*128
        self.compare(self.response(bundle=bundle),'response',False)
    def test_changed_complete_signatures_network_and_domain_never_reuse_authentication(self):
        for mode,value,node,kind in [('exchange',self.bundle(),self.source,'exchange'),('challenge',self.hello(),self.destination,'tcp-challenge'),
                ('request',self.request(),self.source,'tcp-request'),('response',self.response(),self.destination,'tcp-response')]:
            self.compare(value,mode)
            for field,changed in [('signature','0'*128),('public_key','0'*64),('extra',None)]:
                bad=copy.deepcopy(value);bad[field]=changed;self.compare(bad,mode,False)
            bad=self.sign(node,'inventory',value['body']);self.compare(bad,mode,False)
        with self.assertRaises(ValueError):native.check_challenge(self.hello(),'f'*64,self.destination.id,self.pin)
    def test_reduced_exchange_bytes_and_list_limits_do_not_relax_validation(self):
        for name,limit,value in [('MAX_NODES',0,self.bundle(adverts=[None])),('MAX_PACKET_BATCH',0,self.bundle(transits=[None])),
                ('MAX_MESSAGES',0,self.bundle(receipts=[None]))]:
            with patch.object(mesh,name,limit),self.assertRaises(ValueError):native.exchange_check(self.destination,value,self.source.id)
            with patch.object(reference,name,limit),self.assertRaises(ValueError):reference.exchange_check(self.destination,value,self.source.id)
        for mode,value in [('request',self.request()),('response',self.response())]:
            with patch.object(mesh,'MAX_BATCH',1):self.compare(value,mode,False)
        with patch.object(mesh,'MAX_CONTACTS',0),self.assertRaises(ValueError):native.check_request(self.request(),NETWORK,self.destination.id,self.peers,self.nonce)
    def test_default_checks_and_receive_preamble_have_no_python_signature_or_inventory_dispatch(self):
        sent=self.request();reply=self.response(sent);expected=reply['body']['bundle']
        with (patch.object(mesh,'verify',side_effect=AssertionError('Python signature dispatch')),
              patch.object(mesh,'inventory_check',side_effect=AssertionError('Python inventory dispatch'))):
            self.assertEqual(tcp.check_response(reply,NETWORK,self.source.id,self.destination.id,sent),expected)
            self.assertEqual(tcp.check_request(sent,NETWORK,self.destination.id,self.peers,self.nonce),sent['body'])
            self.assertEqual(tcp.check_challenge(self.hello(),NETWORK,self.destination.id,self.pin),'4'*64)
            self.destination.receive(self.bundle(),self.source.id)
    def test_outer_success_never_accepts_bad_items_or_changes_state_before_full_checks(self):
        value=self.bundle(adverts=[None]);self.compare(value,'exchange')
        before=copy.deepcopy(self.destination.state);disk=self.destination.path.read_bytes()
        with self.assertRaises(ValueError):self.destination.receive(value,self.source.id)
        self.assertEqual(self.destination.state,before);self.assertEqual(self.destination.path.read_bytes(),disk)
    def test_response_body_operation_authority_and_current_provider_bindings(self):
        value=self.hello();engine=crypto.backend();call=engine.call
        for field,changed in [('mode','response'),('body',{}),('envelope_authenticated',1),('ledger_authority',0),('durable_custody_acknowledgment',0)]:
            def forged(request):
                result=call(request)
                if type(request) is dict and 'Exchange' in request:result=dict(result);result[field]=changed
                return result
            with patch.object(engine,'call',side_effect=forged),self.assertRaises(ValueError):native.check_challenge(value,NETWORK,self.destination.id,self.pin)
        class Provider:
            def call(self,request):raise ValueError('MODEL_CHANGED_EXCHANGE_PROVIDER_REFUSES')
        with patch.object(crypto,'backend',return_value=Provider()),self.assertRaisesRegex(ValueError,'MODEL_CHANGED_EXCHANGE_PROVIDER_REFUSES'):
            native.check_challenge(value,NETWORK,self.destination.id,self.pin)

if __name__=='__main__':unittest.main()
