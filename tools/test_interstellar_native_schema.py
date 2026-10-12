"""Native signature/schema gates against independent re-signed Python adversaries."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_schema_native as native
import interstellar_schema_reference as reference
from interstellar_crypto import backend
from test_interstellar_mesh import Fixture,NETWORK

class SchemaTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-native-schema-');self.addCleanup(temporary.cleanup)
        self.f=Fixture(temporary.name);self.source=self.f.node('earth');self.destination=self.f.node('proxima')
        self.addCleanup(self.source.close);self.addCleanup(self.destination.close)
    def body(self,node):return dict(format=mesh.VERSION,network=NETWORK,node_id=node.id)
    def sign(self,kind,body,node=None):return mesh.sign((node or self.source).key,kind,body)
    def route(self,**fields):
        body=dict(self.body(self.source),packet_id='3'*64,destination=self.destination.id,frame_id='4'*64)
        body.update(fields);return self.sign('receipt-route',body)
    def receipt(self,route=None,**fields):
        body=dict(self.body(self.destination),packet_id='3'*64,frame_id='4'*64,routing=route or self.route(),outcome='EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
        body.update(fields);return self.sign('receipt',body,self.destination)
    def compare(self,value,kind,accepted=True):
        function={'advert':reference.advert_check,'inventory':reference.inventory_check,
                  'receipt-route':reference.receipt_route_check,'receipt':reference.receipt_check}[kind]
        if accepted:
            expected=function(value,NETWORK);actual=native.check(value,kind,NETWORK)
            self.assertEqual(actual['packet_id'] if kind=='receipt' else actual,expected)
        else:
            for check in (lambda:function(value,NETWORK),lambda:native.check(value,kind,NETWORK)):
                with self.assertRaises(ValueError):check()
    def test_exact_signed_valid_body_boundaries_and_default_native_gate(self):
        peers=sorted(f'{n:064x}' for n in range(16));ids=[f'{n:064x}' for n in range(256)]
        for sequence,label in [(1,'A'),(2**63-1,'\x7f'*80)]:
            value=self.sign('advert',dict(self.body(self.source),region='2'*64,label=label,sequence=sequence,neighbors=peers))
            self.compare(value,'advert');self.assertEqual(mesh.advert_check(value,NETWORK),value['body'])
        value=self.sign('inventory',dict(self.body(self.source),packet_ids=ids));self.compare(value,'inventory')
        self.assertEqual(mesh.inventory_check(value,NETWORK),value['body'])
        self.compare(self.route(),'receipt-route');receipt=self.receipt();self.compare(receipt,'receipt')
        self.assertEqual(mesh.receipt_check(receipt,NETWORK),'3'*64)
    def test_resigned_advert_field_type_order_self_label_and_integer_rejections(self):
        original=dict(self.body(self.source),region='2'*64,label='ground',sequence=1,neighbors=['3'*64,'4'*64])
        changes=[('region','A'*64),('label',''),('label','x'*81),('label','中文'),('label','\n'),
                 ('sequence',True),('sequence',1.0),('sequence',0),('sequence',-1),('sequence',2**63),
                 ('neighbors',None),('neighbors',[None]),('neighbors',['4'*64,'3'*64]),
                 ('neighbors',['3'*64]*2),('neighbors',[self.source.id]),('neighbors',['bad']),
                 ('neighbors',[f'{n:064x}' for n in range(17)]),('extra',True)]
        for name,value in changes:
            with self.subTest(field=name,value=value):
                body=dict(original);body[name]=value;self.compare(self.sign('advert',body),'advert',False)
    def test_resigned_inventory_capacity_order_duplicate_hex_and_type_rejections(self):
        for values in (None,[False],['bad'],['3'*64]*2,['4'*64,'3'*64],[f'{n:064x}' for n in range(257)]):
            self.compare(self.sign('inventory',dict(self.body(self.source),packet_ids=values)),'inventory',False)
        self.compare(self.sign('inventory',dict(self.body(self.source),packet_ids=[],extra=0)),'inventory',False)
    def test_route_and_destination_receipt_resigned_bindings_remain_separate(self):
        for field in ('packet_id','destination','frame_id'):
            self.compare(self.route(**{field:'invalid'}),'receipt-route',False)
        self.compare(self.route(extra=0),'receipt-route',False)
        for field,value in [('packet_id','5'*64),('frame_id','5'*64),('outcome','LEDGER_ACCEPTED'),('extra',None)]:
            self.compare(self.receipt(**{field:value}),'receipt',False)
        self.compare(self.receipt(route=self.route(destination=self.source.id)),'receipt',False)
        route=self.route();route['signature']='0'*128
        self.compare(self.receipt(route=route),'receipt',False)
    def test_changed_signature_nested_body_network_identity_and_kind_never_reuse_authentication(self):
        value=self.receipt();self.compare(value,'receipt')
        for location in ('signature','public_key','body','routing'):
            bad=copy.deepcopy(value)
            if location=='signature':bad['signature']='0'*128
            elif location=='public_key':bad['public_key']=self.source.key.identity['public_key']
            elif location=='body':bad['body']['frame_id']='5'*64
            else:bad['body']['routing']['body']['frame_id']='5'*64
            self.compare(bad,'receipt',False)
        with self.assertRaises(ValueError):native.check(value,'inventory',NETWORK)
        with self.assertRaises(ValueError):native.check(value,'receipt','f'*64)
    def test_smaller_limits_and_no_python_schema_signature_fallback(self):
        advert=self.sign('advert',dict(self.body(self.source),region='2'*64,label='x',sequence=1,neighbors=['3'*64]))
        inventory=self.sign('inventory',dict(self.body(self.source),packet_ids=['3'*64]))
        for module in (mesh,reference):
            with patch.object(module,'MAX_CONTACTS',0):
                with self.assertRaises(ValueError):
                    native.check(advert,'advert',NETWORK) if module is mesh else reference.advert_check(advert,NETWORK)
            with patch.object(module,'MAX_MESSAGES',0):
                with self.assertRaises(ValueError):
                    native.check(inventory,'inventory',NETWORK) if module is mesh else reference.inventory_check(inventory,NETWORK)
        with (patch.object(mesh,'verify',side_effect=AssertionError('Python schema verify dispatch')),
              patch.object(reference,'verify',side_effect=AssertionError('Python fallback'))):
            self.assertEqual(mesh.advert_check(advert,NETWORK),advert['body'])
            self.assertEqual(mesh.receipt_check(self.receipt(),NETWORK),'3'*64)
    def test_returned_body_and_authority_flags_are_bound(self):
        value=self.route();engine=backend();call=engine.call
        def forged(request):
            result=call(request)
            if type(request) is dict and 'Schema' in request:
                result=dict(result);result['ledger_authority']=0
            return result
        with patch.object(engine,'call',side_effect=forged),self.assertRaises(ValueError):native.check(value,'receipt-route',NETWORK)

if __name__=='__main__':unittest.main()
