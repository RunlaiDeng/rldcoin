"""Independent original configuration/endpoint and actual directory adversaries."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import interstellar_mesh as mesh
import interstellar_config_native as native
import interstellar_config_reference as reference
import interstellar_crypto as crypto
import interstellar_process_lock as locks
from test_interstellar_mesh import NETWORK

class ConfigTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-native-config-');self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name).resolve();self.node='1'*64;self.peer='2'*64
    def config(self,contacts):return dict(format=mesh.VERSION,state=str(self.root/'state'),network=NETWORK,contacts=contacts)
    def tcp(self,**changes):
        value=dict(peer=self.peer,host='127.0.0.1',port=12345,tls_cert_sha256='3'*64);value.update(changes);return value
    def spool(self,**changes):
        value=dict(peer=self.peer,inbox=str(self.root/'inbox'),outbox=str(self.root/'outbox'));value.update(changes);return value
    def compare(self,contacts,accepted=True):
        config=self.config(contacts)
        functions=(lambda:reference.contacts(SimpleNamespace(id=self.node),config),lambda:native.contacts(config,self.node))
        if accepted:self.assertEqual(functions[0](),functions[1]())
        else:
            for check in functions:
                with self.assertRaises((ValueError,TypeError,OSError)):check()
    def test_valid_tcp_spool_compression_and_oneway_shapes_preserve_original_contacts(self):
        for value in [self.tcp(),dict(peer=self.peer,host='240.0.0.1',port=65535),self.spool(),
                self.spool(adapter=mesh.spool_codec.FORMAT),dict(peer=self.peer,adapter=mesh.SPOOL_ONEWAY,inbox=str(self.root/'one-in')),
                dict(peer=self.peer,adapter=mesh.SPOOL_ONEWAY,outbox=str(self.root/'one-out'))]:
            self.assertIs(native.contact_schema(value),value);self.assertEqual(reference.contact_schema(value),value);self.compare([value])
        value=self.spool(inbox=self.root/'path-in',outbox=self.root/'path-out')
        self.assertIs(native.contact_schema(value),value);self.compare([value])
    def test_exact_fields_adapter_types_self_duplicate_and_peer_identifiers_refuse(self):
        for value in [None,[],{},self.tcp(extra=0),self.tcp(peer='bad'),self.tcp(peer=self.node),self.tcp(tls_cert_sha256='A'*64),
                dict(peer=self.peer,host='127.0.0.1'),self.spool(adapter='unknown'),self.spool(adapter=mesh.SPOOL_ONEWAY),
                dict(peer=self.peer,adapter=mesh.SPOOL_ONEWAY)]:self.compare([value],False)
        self.compare([self.tcp(),self.tcp()],False)
    def test_original_ipv4_and_actual_integer_port_boundaries(self):
        for host,port,listening in [('127.0.0.1',1,False),('127.0.0.1',65535,False),('240.0.0.1',80,False),
                ('0.0.0.0',0,True),('0.0.0.0',65535,True),('255.255.255.254',10,False)]:
            self.assertEqual(reference.tcp_endpoint(host,port,listening),native.tcp_endpoint(host,port,listening))
            self.assertEqual(mesh.tcp_endpoint(host,port,listening),native.tcp_endpoint(host,port,listening))
        for host,port,listening in [('example.com',80,False),('::1',80,False),('127.00.0.1',80,False),('127.0.0.1 ',80,False),
                ('224.0.0.1',80,False),('239.255.255.255',0,True),('255.255.255.255',0,True),('0.0.0.0',1,False),
                ('127.0.0.1',0,False),('127.0.0.1',65536,True),('127.0.0.1',-1,True),('127.0.0.1',True,False),('127.0.0.1',1.0,False)]:
            for check in (reference.tcp_endpoint,native.tcp_endpoint):
                with self.assertRaises(ValueError):check(host,port,listening)
    def test_header_and_identifier_validation_remain_before_correct_constructor_phases(self):
        valid=self.config([]);native.header(valid);self.assertEqual(native.identifier(NETWORK),mesh.hex32(NETWORK))
        for config in [None,[],{},dict(valid,extra=0),dict(valid,format='old')]:
            with self.assertRaises(ValueError):native.header(config)
        for value in [None,False,'A'*64,'a'*63]:
            for check in (mesh.hex32,native.identifier):
                with self.assertRaises(ValueError):check(value)
        bad=dict(valid,network='bad')
        with self.assertRaises(ValueError):mesh.Node(bad)
        self.assertTrue((self.root/'state').is_dir())
    def test_capacity16_and_reduced_caller_limit_unchanged(self):
        contacts=[dict(peer=f'{n+100:064x}',host='127.0.0.1',port=n+1) for n in range(16)]
        self.compare(contacts);self.compare(contacts+[dict(peer='f'*64,host='127.0.0.1',port=80)],False)
        for values in [None,{},()]:self.compare(values,False)
        with patch.object(mesh,'MAX_CONTACTS',0),self.assertRaises(ValueError):native.contacts(self.config([self.tcp()]),self.node)
        with patch.object(reference,'MAX_CONTACTS',0),self.assertRaises(ValueError):reference.contacts(SimpleNamespace(id=self.node),self.config([self.tcp()]))
    def test_distinct_spool_paths_native_nofollow_and_original_creation_order(self):
        self.compare([self.spool(inbox=str(self.root/'same'),outbox=str(self.root/'same'))],False)
        self.compare([self.spool(),self.spool(peer='4'*64,inbox=str(self.root/'other-in'))],False)
        target=self.root/'real';target.mkdir();link=self.root/'linked';link.symlink_to(target,target_is_directory=True)
        self.compare([self.spool(inbox=str(link))],False)
        for label,check in [('python',lambda cfg:reference.contacts(SimpleNamespace(id=self.node),cfg)),('native',lambda cfg:native.contacts(cfg,self.node))]:
            incoming=self.root/(label+'-first-in');outgoing=self.root/(label+'-first-out');later=self.root/(label+'-later')
            config=self.config([self.spool(inbox=str(incoming),outbox=str(outgoing)),dict(peer='5'*64,inbox=str(later))])
            with self.assertRaises(ValueError):check(config)
            self.assertTrue(incoming.is_dir());self.assertTrue(outgoing.is_dir());self.assertFalse(later.exists())
    def test_actual_constructor_uses_native_checks_and_failure_closes_original_lock(self):
        state=self.root/'actual';identity=mesh.initialize(state,NETWORK,'3'*64,'config ground fixture')
        config=dict(self.config([self.tcp()]),state=str(state));before=locks.usage()
        with (patch.object(mesh,'contact_schema',side_effect=AssertionError('Python contact dispatch')),
              patch.object(mesh,'tcp_endpoint',side_effect=AssertionError('Python endpoint dispatch'))):
            with mesh.Node(config) as node:self.assertEqual(node.contacts[self.peer],{k:v for k,v in self.tcp().items() if k!='peer'})
        self.assertEqual(locks.usage(),before)
        config['contacts']=[self.tcp(peer=identity['node_id'])]
        with self.assertRaises(ValueError):mesh.Node(config)
        self.assertEqual(locks.usage(),before)
    def test_current_provider_and_literal_flags_and_configured_output_binding(self):
        engine=crypto.backend();call=engine.call
        for field,value in [('configured_input_only',1),('ledger_authority',0),('custody_acknowledgment',0),('mode','shape')]:
            def forged(request):
                result=call(request)
                if type(request) is dict and 'Config' in request:result=dict(result);result[field]=value
                return result
            with patch.object(engine,'call',side_effect=forged),self.assertRaises(ValueError):native.tcp_endpoint('127.0.0.1',80)
        def changed_contact(request):
            result=call(request)
            if type(request) is dict and type(request.get('Config')) is dict and 'Resolve' in request['Config']:
                result=copy.deepcopy(result);result['value']['contact']['host']='192.0.2.1'
            return result
        with patch.object(engine,'call',side_effect=changed_contact),self.assertRaises(ValueError):native.contacts(self.config([self.tcp()]),self.node)
        class Provider:
            def call(self,request):raise ValueError('MODEL_CHANGED_CONFIG_PROVIDER_REFUSES')
        with patch.object(crypto,'backend',return_value=Provider()),self.assertRaisesRegex(ValueError,'MODEL_CHANGED_CONFIG_PROVIDER_REFUSES'):
            native.tcp_endpoint('127.0.0.1',80)

if __name__=='__main__':unittest.main()
