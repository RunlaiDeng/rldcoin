"""Discovery, custody, hostile input and restart checks for the mesh prototype."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as evidence

NETWORK = 'a' * 64


class Fixture:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.names = ['earth', 'proxima', 'andromeda']
        self.identities = {name: mesh.initialize(self.root / name, NETWORK, str(i + 1) * 64, name)
                           for i, name in enumerate(self.names)}
        self.configs = {}
        for i, name in enumerate(self.names):
            contacts = []
            for j, other in enumerate(self.names):
                if abs(i - j) == 1:
                    contacts.append({'peer': self.identities[other]['node_id'],
                                     'inbox': str(self.root / 'links' / (other + '-' + name)),
                                     'outbox': str(self.root / 'links' / (name + '-' + other))})
            self.configs[name] = {'format': mesh.VERSION, 'state': str(self.root / name),
                                  'network': NETWORK, 'contacts': contacts}

    def node(self, name):
        return mesh.Node(self.configs[name])

    def rounds(self, count=6, names=None):
        for _ in range(count):
            for name in names or self.names:
                with self.node(name) as node:
                    result = node.tick()
                    if result['errors']:
                        raise ValueError(result['errors'])

    def frame(self):
        return evidence.make_frame('source-finality', '1' * 64, '3' * 64, '4' * 64,
                                   b'{"ground_fixture":"requires separate ledger validation"}')


class MeshTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.f = Fixture(self.temporary.name)

    def _arrival_before_recent_eviction(self, full):
        self.f.rounds();peer=self.f.identities['proxima']['node_id'];destination=self.f.identities['andromeda']['node_id']
        with self.f.node('earth') as node:
            for _ in range(10):node.enqueue_batch([(self.f.frame(),destination)]*4)
            node.prepare_exchange(peer)
            if full:
                node.state['first_carriage'][peer]=node.first_carriage_plan(peer)
                self.assertEqual(len(node.state['first_carriage'][peer]['pending']),32)
                node.save()
            target=node.enqueue(self.f.frame(),destination)
            original=copy.deepcopy(node.state['messages'][target])
            for _ in range(8):node.enqueue_batch([(self.f.frame(),destination)]*4)
            self.assertNotIn(target,node.state['recent_transits'])
            self.assertNotIn(target,node.state['first_carriage'][peer]['pending'])
            self.assertIn(target,node.state['first_arrivals'])
            # A fresh exact authenticated outgoing hop can be suppressed without
            # granting a destination receipt. This forces a durable waiting test
            # even if ordinary rotation would otherwise choose the target early.
            outgoing=node.exchange(peer,retry_packet_ids=(target,))['body']['transits'][0]
            self.assertEqual(mesh.digest(outgoing['packet']),target)
            suppressed={mesh.digest(outgoing)}
            state=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('arrival publication failure')):
                with self.assertRaises(OSError):node.prepare_exchange(peer,suppressed)
            self.assertEqual(node.state,state);self.assertEqual(node.path.read_bytes(),raw)
            node.prepare_exchange(peer,suppressed)
            first=node.state['first_carriage'][peer]
            self.assertIn(target,first['arrivals']+first['pending'])
            self.assertNotIn(target,first['prepared']);node.validate_state()
            order=list(node.state['first_arrivals']);metadata=copy.deepcopy(first)
        found=None
        for turn in range(17):
            with mesh._carriage_position_lock:
                mesh._carriage_positions.clear();mesh._carriage_position_bytes=0
            with self.f.node('earth') as node:
                if turn==0:
                    self.assertEqual(node.state['first_arrivals'],order)
                    self.assertEqual(node.state['first_carriage'][peer],metadata)
                self.assertEqual(node.state['messages'][target],original)
                ids={mesh.digest(t['packet']) for t in node.prepare_exchange(peer)['body']['transits']}
                node.validate_state()
                if target in ids:found=turn+1;break
        self.assertIsNotNone(found)
        with self.f.node('earth') as node:
            first=node.state['first_carriage'][peer]
            self.assertIn(target,first['prepared']);self.assertNotIn(target,first['pending']+first['arrivals'])
            self.assertEqual(node.state['messages'][target],original);self.assertNotIn(target,node.receipts())

    def test_arrival_waiting_survives_preparation_gap_atomic_failure_and_cold_open(self):
        self._arrival_before_recent_eviction(False)

    def test_arrival_waiting_survives_full_admission_queue_and_cold_open(self):
        self._arrival_before_recent_eviction(True)

    def test_arrival_metadata_schema_and_original_capacity_refuse_without_write(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            original=copy.deepcopy(node.state);raw=node.path.read_bytes()
            for rows in ([ident,ident],[],['f'*64],['x'],[format(i,'064x') for i in range(257)]):
                node.state=copy.deepcopy(original);node.state['first_arrivals']=rows
                with self.assertRaisesRegex(ValueError,'arrival order|invalid 32-byte identifier'):node.validate_state()
                self.assertEqual(node.path.read_bytes(),raw)
            for field,value in (('arrivals',[format(i,'064x') for i in range(257)]),('observed',[format(i,'064x') for i in range(257)]),('observed','not-a-list'),('next_kind',True),('next_kind',2),('history_after','x')):
                node.state=copy.deepcopy(original);node.state['first_carriage'][peer][field]=value
                with self.assertRaises(ValueError):node.validate_state()
                self.assertEqual(node.path.read_bytes(),raw)
            node.state=copy.deepcopy(original);first=node.state['first_carriage'][peer];first['arrivals']=[ident];first['pending']=[ident]
            with self.assertRaisesRegex(ValueError,'waiting/prepared overlap'):node.validate_state()
            self.assertEqual(node.path.read_bytes(),raw);node.state=original

    def test_first_offer_queue_is_scoped_to_actual_outgoing_branch(self):
        self.f.rounds();left=self.f.identities['earth']['node_id'];right=self.f.identities['andromeda']['node_id']
        with self.f.node('proxima') as node:
            wrong=[node.enqueue(self.f.frame(),right) for _ in range(32)]
            original=copy.deepcopy(node.state['messages'])
            self.assertFalse(node.prepare_exchange(left)['body']['transits'])
            self.assertEqual(node.state['first_carriage'][left]['pending'],[])
            target=node.enqueue(self.f.frame(),left)
            bundle=node.prepare_exchange(left)
            self.assertIn(target,{mesh.digest(t['packet']) for t in bundle['body']['transits']})
            self.assertIn(target,node.state['first_carriage'][left]['prepared'])
            self.assertEqual({i:node.state['messages'][i] for i in wrong},original)
            self.assertFalse(node.state['receipts'])
            # The other branch retains ordinary first service and original bytes.
            right_ids={mesh.digest(t['packet']) for t in node.prepare_exchange(right)['body']['transits']}
            self.assertTrue(right_ids&set(wrong));self.assertNotIn(target,right_ids)

    def test_ineligible_waiting_metadata_changes_only_after_atomic_preparation(self):
        self.f.rounds();left=self.f.identities['earth']['node_id'];right=self.f.identities['andromeda']['node_id']
        with self.f.node('proxima') as node:
            wrong=[node.enqueue(self.f.frame(),right) for _ in range(32)]
            # Route changes may leave valid but currently ineligible metadata.
            node.state['first_carriage'][left]['pending']=wrong;node.save()
            target=node.enqueue(self.f.frame(),left);before=copy.deepcopy(node.state);raw=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('first queue publication failure')):
                with self.assertRaises(OSError):node.prepare_exchange(left)
            self.assertEqual(node.state,before);self.assertEqual(node.path.read_bytes(),raw)
        with self.f.node('proxima') as node:
            self.assertIn(target,{mesh.digest(t['packet']) for t in node.prepare_exchange(left)['body']['transits']})
            self.assertFalse(node.state['first_carriage'][left]['pending'])
            self.assertEqual(node.state['messages'],before['messages']);self.assertFalse(node.state['receipts'])

    def test_first_offer_survives_recent_eviction_and_cold_positions(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            initial=[node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id']) for _ in range(40)]
            old=set(initial)-set(node.state['recent_transits'])
            first=node.prepare_exchange(peer)
            carried={mesh.digest(t['packet']) for t in first['body']['transits']}
            self.assertTrue(carried&old)  # ordinary historical service still runs
            queue=node.state['first_carriage'][peer]['pending']
            self.assertLessEqual(len(queue),mesh.MAX_RECENT_TRANSITS)
            target=queue[-1];original=copy.deepcopy(node.state['messages'][target])
            for _ in range(40):node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            self.assertNotIn(target,node.state['recent_transits'])
        found=None
        for turn in range(16):
            with mesh._carriage_position_lock:
                mesh._carriage_positions.clear();mesh._carriage_position_bytes=0
            with self.f.node('earth') as node:
                self.assertEqual(node.state['messages'][target],original)
                ids={mesh.digest(t['packet']) for t in node.prepare_exchange(peer)['body']['transits']}
                if target in ids:found=turn+1;break
        self.assertIsNotNone(found)
        with self.f.node('earth') as node:
            self.assertIn(target,node.state['first_carriage'][peer]['prepared'])
            self.assertNotIn(target,node.state['first_carriage'][peer]['pending'])
            self.assertNotIn(target,node.receipts())
            self.assertEqual(node.state['messages'][target],original)

    def test_first_offer_authentication_and_failed_atomic_do_not_publish_metadata(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            before=node.path.read_bytes();state=copy.deepcopy(node.state)
            node.state['messages'][ident]['packet']['signature']='0'*128
            with self.assertRaises(ValueError):node.prepare_exchange(peer)
            self.assertEqual(node.path.read_bytes(),before)
            node.state=copy.deepcopy(state)
            with patch.object(mesh,'atomic',side_effect=OSError('first offer publication failure')):
                with self.assertRaises(OSError):node.prepare_exchange(peer)
            self.assertEqual(node.state,state)
            self.assertEqual(node.path.read_bytes(),before)

    def test_first_offer_metadata_schema_and_original_capacities_refuse(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            original=copy.deepcopy(node.state['first_carriage']);before=node.path.read_bytes()
            invalid=[{**mesh.empty_first_carriage(),'pending':[ident],'prepared':[ident]},
                {**mesh.empty_first_carriage(),'pending':[format(i,'064x') for i in range(33)],'prepared':[]},
                {**mesh.empty_first_carriage(),'pending':[],'prepared':[format(i,'064x') for i in range(257)]},
                {**mesh.empty_first_carriage(),'pending':['x'],'prepared':[]},{**mesh.empty_first_carriage(),'pending':[],'prepared':[],'authority':True}]
            for value in invalid:
                node.state['first_carriage'][peer]=value
                with self.assertRaises(ValueError):node.validate_state()
                self.assertEqual(node.path.read_bytes(),before)
            node.state['first_carriage']=original

    def test_retry_preserves_ordinary_positions_and_retains_original_packets(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            for _ in range(8):node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            first=node.prepare_exchange(peer)
            ids=tuple(mesh.digest(t['packet']) for t in first['body']['transits'])
            positions={k:copy.deepcopy(node.state[k]) for k in ('transit_cursors','recent_transit_cursors','history_transit_cursors','transit_class_steps','first_carriage')}
            replay=node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(tuple(mesh.digest(t['packet']) for t in replay['body']['transits']),ids)
            self.assertEqual({k:node.state[k] for k in positions},positions)
            following=node.prepare_exchange(peer)
            self.assertTrue({mesh.digest(t['packet']) for t in following['body']['transits']}-set(ids))
            self.assertTrue(set(ids)<=set(node.state['messages']))
            self.assertFalse(set(ids)&set(node.receipts()))

    def test_retry_still_authenticates_and_obeys_suppression(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            first=node.prepare_exchange(peer);ids=(ident,)
            replay=node.exchange(peer,{mesh.digest(t) for t in first['body']['transits']},ids)
            self.assertEqual(replay['body']['transits'],[])
            original=copy.deepcopy(node.state['messages'][ident]);before=node.path.read_bytes()
            node.state['messages'][ident]['packet']['signature']='0'*128
            with self.assertRaises(ValueError):node.prepare_exchange(peer,retry_packet_ids=ids)
            self.assertEqual(node.path.read_bytes(),before)
            node.state['messages'][ident]=original
            for invalid in ([ident],(ident,ident),('x',),tuple(str(i)*64 for i in range(5))):
                with self.assertRaises(ValueError):node.exchange(peer,retry_packet_ids=invalid)

    def test_retry_hint_is_bounded_scoped_and_forgettable(self):
        self.f.rounds();peer=self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            domain=node.carriage_position_domain();ids=('1'*64,)
            mesh.remember_carriage_position((domain,peer,'failed-carriage'),ids)
            self.assertEqual(node.failed_carriage(peer),ids)
            with patch.object(mesh,'MAX_PACKET_BATCH',3):self.assertEqual(node.failed_carriage(peer),())
            node.forget_failed_carriage(peer)
            self.assertEqual(node.failed_carriage(peer),())
            with patch.object(mesh,'MAX_CARRIAGE_POSITIONS',2):
                for i in range(5):mesh.remember_carriage_position((domain,peer,'test',i),ids)
                self.assertLessEqual(len(mesh._carriage_positions),2)
                self.assertLessEqual(mesh._carriage_position_bytes,mesh.MAX_CARRIAGE_POSITION_BYTES)

    def test_previous_scheduler_identity_refuses_without_rewrite(self):
        path=self.f.root/'earth/identity.private.json'
        identity=json.loads(path.read_text());identity['transit_scheduler']='RLD-CONTACT-TRANSIT-SCHEDULER-V7'
        path.write_text(json.dumps(identity));before=path.read_bytes()
        with self.assertRaises(ValueError):self.f.node('earth')
        self.assertEqual(path.read_bytes(),before)

    def routed_fixture(self, names, edges):
        root=self.f.root/'routed'
        ids={n:mesh.initialize(root/n,NETWORK,str(i+1)*64,n)['node_id'] for i,n in enumerate(names)}
        configs={n:{'format':mesh.VERSION,'state':str(root/n),'network':NETWORK,'contacts':[]} for n in names}
        for a,b in edges:
            for source,target in [(a,b),(b,a)]:
                configs[source]['contacts'].append({'peer':ids[target],
                    'inbox':str(root/'links'/(target+'-'+source)),'outbox':str(root/'links'/(source+'-'+target))})
        # Discovery alone: no packets have yet been created.
        for _ in range(5):
            for a,b in [(s,t) for edge in edges for s,t in [edge,edge[::-1]]]:
                with mesh.Node(configs[a]) as node:bundle=node.exchange(ids[b])
                with mesh.Node(configs[b]) as node:node.receive(bundle,ids[a])
        return ids,configs

    def authenticated_transits(self, count=1):
        self.f.rounds()
        with self.f.node('earth') as node:
            for _ in range(count):
                node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            transits=node.exchange(self.f.identities['proxima']['node_id'])['body']['transits']
        with mesh._verified_transits_lock:
            mesh._verified_transits.clear()
        return transits

    def completed_local(self, count=1):
        with self.f.node('earth') as node:
            ids=[node.enqueue(self.f.frame(),node.id) for _ in range(count)]
        return ids

    def test_completed_archive_reopens_exact_frame_and_keeps_scoped_receipt(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            original=node.state['messages'][ident]
            self.assertEqual(node.archive_completed(),1)
            self.assertNotIn(ident,node.state['messages'])
            self.assertEqual(node.transit(ident),original)
            self.assertEqual(node.summaries()[ident]['frame_id'],original['routing']['body']['frame_id'])
        with self.f.node('earth') as node:
            path=self.f.root/'restored-frame.json'
            node.export_received(ident,path)
            self.assertEqual(path.read_bytes(),self.f.frame())
            self.assertIn(ident,node.receipts())
            self.assertFalse(node.status()['payment_authorized'])

    def test_default_early_archive_keeps_pending_evidence_and_every_completed_payload(self):
        completed=self.completed_local(mesh.ARCHIVE_HIGH_WATER)
        with self.f.node('earth') as node:
            pending=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            original=copy.deepcopy(node.state['messages'])
            receipts=copy.deepcopy(node.receipts())
            moved=node.archive_completed()
            self.assertGreater(moved,0)
            self.assertLessEqual(moved,mesh.MAX_ARCHIVE_BATCH)
            self.assertIn(pending,node.state['messages'])
            self.assertNotIn(pending,node.state['archives'])
            self.assertNotIn(pending,node.receipts())
        with self.f.node('earth') as node:
            self.assertEqual(node.receipts(),receipts)
            for ident in completed+[pending]:
                self.assertEqual(node.transit(ident),original[ident])
            self.assertFalse(node.status()['payment_authorized'])

    def test_archive_failure_before_payload_custody_preserves_active_state(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            with patch.object(mesh,'archive_write',side_effect=OSError('injected archive custody failure')):
                with self.assertRaisesRegex(OSError,'custody failure'):node.archive_completed()
            self.assertEqual(node.path.read_bytes(),before)
            self.assertIn(ident,node.state['messages'])
            self.assertEqual(node.state['archives'],{})

    def test_archive_index_failure_keeps_active_and_recovers_complete_orphan(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('injected archive index failure')):
                with self.assertRaisesRegex(OSError,'index failure'):node.archive_completed()
            self.assertEqual(node.path.read_bytes(),before)
            files=list(node.archive_root.glob('*.json'))
            self.assertEqual(len(files),2);raw={p:p.read_bytes() for p in files}
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            self.assertIn(ident,node.state['messages'])
            self.assertEqual(node.archive_completed(),1)
            self.assertEqual({p:p.read_bytes() for p in files},raw)
            self.assertNotIn(ident,node.state['messages'])

    def test_archive_full_preserves_active_and_does_not_remove_existing_files(self):
        self.completed_local()
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            before=node.path.read_bytes()
            for field,limit in [('MAX_ARCHIVE_FILES',0),('MAX_ARCHIVE_BYTES',1)]:
                with patch.object(mesh,field,limit),self.assertRaisesRegex(ValueError,'capacity'):
                    node.archive_completed()
                self.assertEqual(node.path.read_bytes(),before)
            self.assertEqual(list(node.archive_root.iterdir()),[])

    def test_archive_payload_corruption_is_refused_when_read_or_reacknowledged(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.archive_completed();entry=node.state['archives'][ident]['body']
            path=node.archive_root/(entry['file_id']+'.json');raw=path.read_bytes()
            index=raw.index(b'"signature":"')+len(b'"signature":"')
            bad=raw[:index]+(b'0' if raw[index:index+1]!=b'0' else b'1')+raw[index+1:]
            self.assertEqual(len(raw),len(bad));path.write_bytes(bad)
            before=node.path.read_bytes()
            with self.assertRaisesRegex(ValueError,'bytes differ'):node.transit(ident)
            self.assertEqual(node.path.read_bytes(),before)
            self.assertEqual(path.read_bytes(),bad)

    def test_archive_signed_index_tamper_missing_file_and_symlink_refuse(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.archive_completed();state=copy.deepcopy(node.state);path=node.path
            archive=node.archive_root/(state['archives'][ident]['body']['file_id']+'.json')
        bad=copy.deepcopy(state);bad['archives'][ident]['body']['frame_id']='f'*64
        mesh.atomic(path,bad);before=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'signature'):self.f.node('earth')
        self.assertEqual(path.read_bytes(),before)
        mesh.atomic(path,state);raw=archive.read_bytes();archive.unlink()
        with self.assertRaisesRegex(ValueError,'missing'):self.f.node('earth')
        external=self.f.root/'retained.json';external.write_bytes(raw);archive.symlink_to(external)
        with self.assertRaisesRegex(ValueError,'unsafe archive'):self.f.node('earth')
        self.assertEqual(external.read_bytes(),raw)

    def archived_index_fixture(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.archive_completed()
            state=copy.deepcopy(node.state)
            archive=node.archive_root/(state['archives'][ident]['body']['file_id']+'.json')
            path=node.path
        with mesh._verified_archive_index_lock:mesh._verified_archive_index=None
        return ident,path,state,archive

    def test_exact_archive_index_witness_reuses_only_immutable_verified_metadata(self):
        _,path,_,_=self.archived_index_fixture();before=path.read_bytes()
        validator=mesh.Node.archive_entry
        with patch.object(mesh.Node,'archive_entry',autospec=True,side_effect=validator) as checked:
            with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,1)
            with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,1)
            with mesh._verified_archive_index_lock:
                witness=mesh._verified_archive_index
                self.assertIsInstance(witness[1],bytes)
                self.assertTrue(all(isinstance(row,tuple) for row in witness[2]))
                mesh._verified_archive_index=None # Fresh process has no witness.
            with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,2)
        self.assertEqual(path.read_bytes(),before)

    def test_archive_index_witness_reauthenticates_changed_signature_and_domain_limits(self):
        ident,path,state,_=self.archived_index_fixture()
        with self.f.node('earth'):pass
        bad=copy.deepcopy(state);bad['archives'][ident]['signature']='0'*128
        mesh.atomic(path,bad);retained=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'signature'):self.f.node('earth')
        self.assertEqual(path.read_bytes(),retained)
        mesh.atomic(path,state)
        with self.f.node('earth'):pass
        validator=mesh.Node.archive_entry
        with patch.object(mesh.Node,'archive_entry',autospec=True,side_effect=validator) as checked:
            with patch.object(mesh,'MAX_STATE',mesh.MAX_STATE-1):
                with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,1)
            with patch.object(evidence,'KINDS',set()):
                with self.assertRaisesRegex(ValueError,'kind'):self.f.node('earth')
            self.assertEqual(checked.call_count,2)

    def test_warm_archive_index_still_checks_inventory_and_authenticates_changed_payload(self):
        ident,path,_,archive=self.archived_index_fixture()
        with self.f.node('earth'):pass
        before=path.read_bytes();raw=archive.read_bytes()
        index=raw.index(b'"signature":"')+len(b'"signature":"')
        bad=raw[:index]+(b'0' if raw[index:index+1]!=b'0' else b'1')+raw[index+1:]
        archive.write_bytes(bad)
        with self.f.node('earth') as node:
            with self.assertRaisesRegex(ValueError,'bytes differ'):node.archived(ident)
        self.assertEqual(archive.read_bytes(),bad)
        archive.unlink()
        with self.assertRaisesRegex(ValueError,'missing'):self.f.node('earth')
        self.assertEqual(path.read_bytes(),before)

    def test_archive_index_witness_budget_falls_back_and_scope_is_store_specific(self):
        _,path,_,_=self.archived_index_fixture();before=path.read_bytes()
        with self.f.node('proxima'):pass
        with self.f.node('earth'):pass
        validator=mesh.Node.archive_entry
        with patch.object(mesh.Node,'archive_entry',autospec=True,side_effect=validator) as checked:
            with patch.object(mesh,'MAX_VERIFIED_ARCHIVE_INDEX_BYTES',1):
                for _ in range(2):
                    with self.f.node('earth'):pass
                self.assertIsNone(mesh._verified_archive_index)
            self.assertEqual(checked.call_count,2)
            with self.f.node('earth'):pass
            with self.f.node('proxima'):pass # One other store evicts the witness.
            with self.f.node('earth'):pass
            self.assertEqual(checked.call_count,4)
        self.assertEqual(path.read_bytes(),before)

    def test_receipt_only_archive_returns_without_claiming_original_payload(self):
        ids,cfg=self.routed_fixture(['source','forward','destination','return'],
            [('source','forward'),('forward','destination'),('destination','return'),('return','source')])
        with mesh.Node(cfg['source']) as node:
            ident=node.enqueue(self.f.frame(),ids['destination']);bundle=node.exchange(ids['forward'])
        with mesh.Node(cfg['forward']) as node:
            node.receive(bundle,ids['source']);bundle=node.exchange(ids['destination'])
        with mesh.Node(cfg['destination']) as node:
            node.receive(bundle,ids['forward']);bundle=node.exchange(ids['return'])
        with mesh.Node(cfg['return']) as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.receive(bundle,ids['destination']);node.archive_completed()
            self.assertNotIn(ident,node.summaries())
            with self.assertRaisesRegex(ValueError,'no frame'):node.transit(ident)
            bundle=node.exchange(ids['source'])
        with mesh.Node(cfg['source']) as node:
            node.receive(bundle,ids['return']);self.assertIn(ident,node.state['receipts'])
            self.assertFalse(node.status()['payment_authorized'])

    def test_receipt_only_archive_then_original_transit_retains_arrival_order_on_cold_open(self):
        ids,cfg=self.routed_fixture(['source','forward','destination','return'],
            [('source','forward'),('forward','destination'),('destination','return'),('return','source')])
        with mesh.Node(cfg['source']) as node:
            ident=node.enqueue(self.f.frame(),ids['destination']);bundle=node.exchange(ids['forward'])
            later=node.exchange(ids['return'])
            self.assertIn(ident,{mesh.digest(t['packet']) for t in later['body']['transits']})
        with mesh.Node(cfg['forward']) as node:
            node.receive(bundle,ids['source']);bundle=node.exchange(ids['destination'])
        with mesh.Node(cfg['destination']) as node:
            node.receive(bundle,ids['forward']);bundle=node.exchange(ids['return'])
        with mesh.Node(cfg['return']) as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            node.receive(bundle,ids['destination']);node.archive_completed()
            with self.assertRaisesRegex(ValueError,'no frame'):node.transit(ident)
            node.receive(later,ids['source'])
            self.assertIn(ident,node.state['messages']);self.assertIn(ident,node.state['first_arrivals'])
            self.assertNotIn(ident,node.state['recent_transits']);node.validate_state()
            original=copy.deepcopy(node.state['messages'][ident])
        with mesh.Node(cfg['return']) as node:
            self.assertEqual(node.state['messages'][ident],original)
            self.assertIn(ident,node.state['first_arrivals']);self.assertIn(ident,node.receipts())
            self.assertFalse(node.status()['payment_authorized'])

    def test_archive_batches_are_bounded_and_unacknowledged_packets_remain_active(self):
        ids=self.completed_local(20)
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            queued=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            self.assertEqual(node.archive_completed(),mesh.MAX_ARCHIVE_BATCH)
            self.assertEqual(node.archive_completed(),4)
            self.assertIn(queued,node.state['messages'])
            self.assertNotIn(queued,node.state['archives'])
            self.assertEqual(set(node.state['archives']),set(ids))

    def test_exact_transit_witness_cannot_authorize_changed_bytes_or_contact(self):
        transit=self.authenticated_transits()[0]
        recipient=self.f.identities['proxima']['node_id']
        sender=self.f.identities['earth']['node_id']
        validator=mesh._transit_check
        with patch.object(mesh,'_transit_check',wraps=validator) as validate:
            expected=mesh.transit_check(transit,NETWORK,recipient,sender)
            expected[2].clear()
            repeated=mesh.transit_check(copy.deepcopy(transit),NETWORK,recipient,sender)
            self.assertEqual(repeated[2],[sender,recipient])
            self.assertEqual(validate.call_count,1)
            for changed in ['packet','routing','hops']:
                candidate=copy.deepcopy(transit)
                signed=candidate[changed][0] if changed=='hops' else candidate[changed]
                signed['signature']='0'*128
                with self.assertRaises(ValueError):
                    mesh.transit_check(candidate,NETWORK,recipient,sender)
            for network,peer,previous in [('b'*64,recipient,sender),
                    (NETWORK,self.f.identities['andromeda']['node_id'],sender),
                    (NETWORK,recipient,self.f.identities['andromeda']['node_id'])]:
                with self.assertRaises(ValueError):
                    mesh.transit_check(transit,network,peer,previous)
            self.assertEqual(validate.call_count,7)

    def test_receipt_matching_revalidates_changed_packet_before_using_its_frame_binding(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node:
            transit=copy.deepcopy(node.state['messages'][ident]);receipt=copy.deepcopy(node.state['receipts'][ident])
            mesh.receipt_matches(receipt,transit)
            bad=copy.deepcopy(transit);bad['packet']['signature']='0'*128
            with self.assertRaisesRegex(ValueError,'signature'):mesh.receipt_matches(receipt,bad)
            bad=copy.deepcopy(transit);bad['routing']['body']['frame_id']='f'*64
            with self.assertRaisesRegex(ValueError,'signature'):mesh.receipt_matches(receipt,bad)
            with patch.object(evidence,'MAX_FRAME',1),self.assertRaisesRegex(ValueError,'bound'):
                mesh.receipt_matches(receipt,transit)
            self.assertEqual(node.state['messages'][ident],transit)
            self.assertFalse(node.status()['payment_authorized'])

    def test_cold_state_refuses_validly_signed_receipt_for_a_different_frame_binding(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node:
            state=copy.deepcopy(node.state)
            receipt=state['receipts'][ident]
            route=mesh.sign(node.key,'receipt-route',{
                **receipt['body']['routing']['body'],'frame_id':'f'*64})
            altered=mesh.sign(node.key,'receipt',{
                **receipt['body'],'routing':route,'frame_id':'f'*64})
            self.assertEqual(mesh.receipt_check(altered,NETWORK),ident)
            state['receipts'][ident]=altered
            path=node.path
        retained=evidence.canonical(mesh.pack_state_storage(state));path.write_bytes(retained)
        with mesh._verified_transits_lock:mesh._verified_transits.clear()
        with self.assertRaisesRegex(ValueError,'wrong destination receipt'):
            self.f.node('earth')
        self.assertEqual(path.read_bytes(),retained)

    def test_witness_limits_revalidate_and_eviction_preserves_archive(self):
        transits=self.authenticated_transits(3)
        state_path=self.f.root/'earth'/'mesh-state.json'
        before=state_path.read_bytes()
        validator=mesh._transit_check
        with patch.object(mesh,'MAX_VERIFIED_TRANSITS',2),patch.object(mesh,'_transit_check',wraps=validator) as validate:
            for transit in transits:mesh.transit_check(transit,NETWORK)
            self.assertEqual(len(mesh._verified_transits),2)
            mesh.transit_check(transits[0],NETWORK)
            self.assertEqual(validate.call_count,4)
            with patch.object(mesh,'MAX_HOPS',1):
                with self.assertRaisesRegex(ValueError,'bound'):
                    mesh.transit_check(transits[0],NETWORK)
            with patch.object(evidence,'MAX_FRAME',1):
                with self.assertRaisesRegex(ValueError,'bound'):
                    mesh.transit_check(transits[0],NETWORK)
            with patch.object(mesh,'MAX_VERIFIED_TRANSITS',0):
                mesh.transit_check(transits[0],NETWORK)
                mesh.transit_check(transits[0],NETWORK)
                self.assertEqual(len(mesh._verified_transits),0)
            self.assertEqual(validate.call_count,8)
        self.assertEqual(state_path.read_bytes(),before)

    def test_warm_witness_does_not_hide_retained_archive_tampering(self):
        transit=self.authenticated_transits()[0]
        mesh.transit_check(transit,NETWORK)
        path=self.f.root/'earth'/'mesh-state.json'
        state=mesh.load(path,mesh.MAX_STATE)
        ident=mesh.digest(transit['packet'])
        # The source's zero-hop copy remains separately validated. Warm that
        # precise namespace before changing its retained source certificate.
        mesh.transit_check(state['messages'][ident],NETWORK)
        state['messages'][ident]['routing']['signature']='0'*128
        mesh.atomic(path,state)
        before=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'signature'):
            self.f.node('earth')
        self.assertEqual(path.read_bytes(),before)

    def test_receipt_returns_over_a_carrier_without_the_forward_packet(self):
        ids,cfg=self.routed_fixture(['source','forward','destination','return'],
            [('source','forward'),('forward','destination'),('destination','return'),('return','source')])
        with mesh.Node(cfg['source']) as node:
            ident=node.enqueue(self.f.frame(),ids['destination']);bundle=node.exchange(ids['forward'])
        with mesh.Node(cfg['forward']) as node:
            node.receive(bundle,ids['source']);bundle=node.exchange(ids['destination'])
        with mesh.Node(cfg['destination']) as node:
            node.receive(bundle,ids['forward']);bundle=node.exchange(ids['return'])
        self.assertEqual(bundle['body']['transits'],[])
        with mesh.Node(cfg['return']) as node:
            node.receive(bundle,ids['destination'])
            self.assertNotIn(ident,node.state['messages'])
            self.assertIn(ident,node.state['receipts'])
            bundle=node.exchange(ids['source'])
        with mesh.Node(cfg['source']) as node:
            node.receive(bundle,ids['return'])
            self.assertIn(ident,node.state['receipts'])
            self.assertIn(ident,node.state['messages'])
            self.assertFalse(node.status()['payment_authorized'])

    def test_unrelated_local_receipts_do_not_flood_other_regions(self):
        ids,cfg=self.routed_fixture(['local','local-destination','remote','remote-destination'],
            [('local','local-destination'),('local','remote'),('remote','remote-destination')])
        for source,target in [('local','local-destination'),('remote','remote-destination')]:
            with mesh.Node(cfg[source]) as node:
                ident=node.enqueue(self.f.frame(),ids[target]);bundle=node.exchange(ids[target])
            with mesh.Node(cfg[target]) as node:
                node.receive(bundle,ids[source]);bundle=node.exchange(ids[source])
            with mesh.Node(cfg[source]) as node:
                node.receive(bundle,ids[target]);self.assertIn(ident,node.state['receipts'])
        with mesh.Node(cfg['local']) as node:bundle=node.exchange(ids['remote'])
        self.assertEqual(bundle['body']['receipts'],[])
        with mesh.Node(cfg['remote']) as node:
            before=set(node.state['receipts']);node.receive(bundle,ids['local'])
            self.assertEqual(set(node.state['receipts']),before)

    def test_destination_cannot_forge_source_receipt_route_and_inventory_is_signed(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident=node.enqueue(self.f.frame(),self.f.identities['andromeda']['node_id'])
            bundle=node.exchange(self.f.identities['proxima']['node_id'])
        with self.f.node('proxima') as node:
            node.receive(bundle,self.f.identities['earth']['node_id']);bundle=node.exchange(self.f.identities['andromeda']['node_id'])
        with self.f.node('andromeda') as node:
            node.receive(bundle,self.f.identities['proxima']['node_id'])
            receipt=node.state['receipts'][ident];base=node.exchange(self.f.identities['proxima']['node_id'])
            hostile=[]
            for field in ('node_id','packet_id','destination','frame_id'):
                altered=copy.deepcopy(receipt)
                altered['body']['routing']['body'][field]='f'*64
                altered=mesh.sign(node.key,'receipt',altered['body'])
                hostile.append(mesh.sign(node.key,'exchange',{**base['body'],'receipts':[altered]}))
            forged=copy.deepcopy(base)
            forged['body']['inventory']['body']['packet_ids']=['f'*64]
            hostile.append(mesh.sign(node.key,'exchange',forged['body']))
        with self.f.node('proxima') as node:
            before=node.path.read_bytes()
            for bundle in hostile:
                with self.assertRaises(ValueError):node.receive(bundle,self.f.identities['andromeda']['node_id'])
                self.assertEqual(node.path.read_bytes(),before)

    def test_v1_configuration_is_refused_without_rewriting_retained_state(self):
        path=self.f.root/'earth/mesh-state.json'
        with self.f.node('earth'):pass
        before=path.read_bytes();cfg=dict(self.f.configs['earth'],format='RLD-CONTACT-MESH-V1')
        with self.assertRaises(ValueError):mesh.Node(cfg)
        self.assertEqual(path.read_bytes(),before)

    def test_automatic_neighbor_exchange_discovers_three_regions_and_two_hop_route(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            destination = self.f.identities['andromeda']['node_id']
            self.assertEqual(len(node.state['adverts']), 3)
            self.assertEqual(len(node.status()['regions']), 3)
            self.assertEqual(node.route(destination), [self.f.identities[n]['node_id'] for n in self.f.names])
            self.assertNotIn(destination, node.contacts)

    def test_incremental_node_addition_supplies_an_alternate_route_after_preferred_relay_stops(self):
        root = self.f.root/'diamond'
        names = ['source', 'left', 'right', 'destination']
        identities = {name: mesh.initialize(root/name, NETWORK, str(i+1)*64, name)
            for i, name in enumerate(names)}
        configs = {name: {'format': mesh.VERSION, 'state': str(root/name),
            'network': NETWORK, 'contacts': []} for name in names}
        def connect(a, b):
            for source, target in [(a,b), (b,a)]:
                configs[source]['contacts'].append({'peer': identities[target]['node_id'],
                    'inbox': str(root/'links'/(target+'-'+source)),
                    'outbox': str(root/'links'/(source+'-'+target))})
        def rounds(active, count=6):
            for _ in range(count):
                for name in active:
                    with mesh.Node(configs[name]) as node:
                        self.assertFalse(node.tick()['errors'])
        connect('source', 'left')
        rounds(['source', 'left'])
        with mesh.Node(configs['source']) as node:
            self.assertEqual(len(node.state['adverts']), 2)
            self.assertIsNone(node.route(identities['destination']['node_id']))
        connect('left', 'destination')
        rounds(['source', 'left', 'destination'])
        with mesh.Node(configs['source']) as node:
            self.assertEqual(len(node.state['adverts']), 3)
            self.assertEqual(len(node.route(identities['destination']['node_id'])), 3)
        connect('source', 'right')
        connect('right', 'destination')
        rounds(names)
        with mesh.Node(configs['source']) as node:
            self.assertEqual(len(node.state['adverts']), 4)
            preferred = node.route(identities['destination']['node_id'])[1]
            ident = node.enqueue(self.f.frame(), identities['destination']['node_id'])
        stopped = next(name for name in ['left','right'] if identities[name]['node_id'] == preferred)
        rounds([name for name in names if name != stopped], 8)
        with mesh.Node(configs['destination']) as node:
            self.assertIn(ident, node.state['receipts'])
            self.assertEqual(len(node.state['messages'][ident]['hops']), 2)
            visited = mesh.transit_check(node.state['messages'][ident], NETWORK)[2]
            self.assertNotIn(preferred, visited)
        with mesh.Node(configs['source']) as node:
            self.assertIn(ident, node.state['receipts'])
            self.assertEqual(len(node.state['messages']), 1)

    def test_exact_multihop_delivery_return_receipt_and_restart(self):
        self.f.rounds()
        raw = self.f.frame()
        with self.f.node('earth') as node:
            ident = node.enqueue(raw, self.f.identities['andromeda']['node_id'])
        self.f.rounds(5)
        with self.f.node('andromeda') as node:
            target = self.f.root / 'received.frame.json'
            node.export_received(ident, target)
            self.assertEqual(target.read_bytes(), raw)
            self.assertEqual(len(node.state['messages'][ident]['hops']), 2)
            self.assertFalse(node.status()['payment_authorized'])
        with self.f.node('earth') as node:
            self.assertEqual(node.status()['messages'][ident], 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED')
            self.assertIn(ident, node.state['messages'])

    def test_disconnected_relay_retains_then_delivers_without_global_timeout(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident = node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
        self.f.rounds(4, ['earth'])
        with self.f.node('earth') as node:
            self.assertEqual(node.status()['messages'][ident], 'QUEUED_WAITING_CONTACT_OR_ROUTE')
        self.f.rounds(4)
        with self.f.node('earth') as node:
            self.assertIn(ident, node.state['receipts'])

    def test_unknown_route_keeps_packet_without_inventing_connection(self):
        with self.f.node('earth') as node:
            ident = node.enqueue(self.f.frame(), 'b' * 64)
            self.assertIsNone(node.route('b' * 64))
            self.assertEqual(node.exchange(self.f.identities['proxima']['node_id'])['body']['transits'], [])
            self.assertIn(ident, node.state['messages'])

    def test_authenticated_malformed_advert_and_frame_raise_clean_rejections(self):
        with self.f.node('earth') as node:
            advert = node.state['adverts'][node.id]
            malformed = mesh.sign(node.key, 'advert', {**advert['body'], 'neighbors': [{}]})
            with self.assertRaisesRegex(ValueError, 'neighbor'):
                mesh.advert_check(malformed, NETWORK)
            for key, value in [('kind', {}), ('payload_b64', 42)]:
                bad = json.loads(self.f.frame())
                bad[key] = value
                with self.assertRaises(ValueError):
                    evidence.inspect_frame(evidence.canonical(bad))

    def test_message_duplicate_is_idempotent_and_sender_keeps_original(self):
        self.f.rounds()
        peer = self.f.identities['proxima']['node_id']
        with self.f.node('earth') as node:
            ident = node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            bundle = node.exchange(peer)
        with self.f.node('proxima') as node:
            node.receive(bundle, self.f.identities['earth']['node_id'])
            node.receive(bundle, self.f.identities['earth']['node_id'])
            self.assertEqual(list(node.state['messages']), [ident])
        with self.f.node('earth') as node:
            self.assertIn(ident, node.state['messages'])

    def test_signed_tamper_wrong_network_and_wrong_contact_are_atomic_rejections(self):
        with self.f.node('earth') as sender:
            bundle = sender.exchange(self.f.identities['proxima']['node_id'])
            tampered = copy.deepcopy(bundle)
            tampered['body']['adverts'][0]['body']['label'] = 'forged'
            foreign = mesh.sign(sender.key, 'exchange', {**bundle['body'], 'network': 'f' * 64})
        with self.f.node('proxima') as receiver:
            before = receiver.path.read_bytes()
            for candidate, peer in [(tampered, self.f.identities['earth']['node_id']),
                                    (foreign, self.f.identities['earth']['node_id']),
                                    (bundle, self.f.identities['andromeda']['node_id'])]:
                with self.assertRaises(ValueError):
                    receiver.receive(candidate, peer)
                self.assertEqual(receiver.path.read_bytes(), before)

    def test_stale_advert_is_ignored_conflicting_same_revision_preserved(self):
        with self.f.node('earth') as sender:
            old = sender.state['adverts'][sender.id]
            newer = mesh.sign(sender.key, 'advert', {**old['body'], 'sequence': 2, 'label': 'updated'})
            conflict = mesh.sign(sender.key, 'advert', {**newer['body'], 'label': 'contradiction'})
            def bundle(advert):
                b = sender.exchange(self.f.identities['proxima']['node_id'])
                return mesh.sign(sender.key, 'exchange', {**b['body'], 'adverts': [advert]})
            new_bundle, old_bundle, conflict_bundle = bundle(newer), bundle(old), bundle(conflict)
        with self.f.node('proxima') as receiver:
            receiver.receive(new_bundle, self.f.identities['earth']['node_id'])
            receiver.receive(old_bundle, self.f.identities['earth']['node_id'])
            self.assertEqual(receiver.state['adverts'][self.f.identities['earth']['node_id']], newer)
            before = receiver.path.read_bytes()
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                receiver.receive(conflict_bundle, self.f.identities['earth']['node_id'])
            self.assertEqual(receiver.path.read_bytes(), before)

    def test_hop_limit_prevents_over_budget_forwarding(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            ident = node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'], 1)
            self.assertEqual(node.exchange(self.f.identities['proxima']['node_id'])['body']['transits'], [])
            self.assertIn(ident, node.state['messages'])

    def test_hop_chain_cannot_be_rewritten_or_shortened_by_next_relay(self):
        self.f.rounds()
        with self.f.node('earth') as source:
            source.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            bundle = source.exchange(self.f.identities['proxima']['node_id'])
        with self.f.node('proxima') as relay:
            relay.receive(bundle, self.f.identities['earth']['node_id'])
            onward = relay.exchange(self.f.identities['andromeda']['node_id'])
            transit = copy.deepcopy(onward['body']['transits'][0])
            transit['hops'].pop(0)
            with self.assertRaisesRegex(ValueError, 'broken'):
                mesh.transit_check(transit, NETWORK, self.f.identities['andromeda']['node_id'], relay.id)
            transit = copy.deepcopy(onward['body']['transits'][0])
            transit['hops'][0]['body']['to'] = self.f.identities['andromeda']['node_id']
            with self.assertRaisesRegex(ValueError, 'signature'):
                mesh.transit_check(transit, NETWORK)

    def test_capacity_refusal_retains_original_and_does_not_consume_inbox(self):
        self.f.rounds()
        with self.f.node('earth') as source:
            ident = source.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            with patch.object(mesh, 'MAX_MESSAGES', 1):
                with self.assertRaisesRegex(ValueError, 'capacity'):
                    source.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            self.assertIn(ident, source.state['messages'])
            bundle = source.exchange(self.f.identities['proxima']['node_id'])
        with self.f.node('proxima') as relay:
            path = self.f.root / 'links' / 'earth-proxima' / (mesh.digest(bundle) + '.json')
            evidence.write_new(path, evidence.canonical(bundle))
            with patch.object(mesh, 'MAX_MESSAGES', 0):
                self.assertTrue(relay.tick()['errors'])
            self.assertTrue(path.exists())
            self.assertEqual(relay.state['messages'], {})
            for field in ['MAX_SPOOL_FILES', 'MAX_SPOOL_BYTES']:
                with patch.object(mesh, field, 0):
                    self.assertTrue(relay.tick()['errors'])
                self.assertTrue(path.exists())
                self.assertEqual(relay.state['messages'], {})

    def test_fake_destination_receipt_cannot_mark_sender_delivered(self):
        self.f.rounds()
        with self.f.node('earth') as sender:
            ident = sender.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            routing = sender.state['messages'][ident]['routing']
        with self.f.node('proxima') as relay:
            fake = mesh.sign(relay.key, 'receipt', {'format': mesh.VERSION, 'network': NETWORK,
                'node_id': relay.id, 'packet_id': ident, 'frame_id': evidence.inspect_frame(self.f.frame())[0]['message_id'],
                'routing': routing,
                'outcome': 'EVIDENCE_STORED_NOT_LEDGER_ACCEPTED'})
            body = relay.exchange(self.f.identities['earth']['node_id'])['body']
            bundle = mesh.sign(relay.key, 'exchange', {**body, 'receipts': [fake]})
        with self.f.node('earth') as sender:
            with self.assertRaisesRegex(ValueError, 'wrong destination receipt'):
                sender.receive(bundle, self.f.identities['proxima']['node_id'])
            self.assertNotIn(ident, sender.state['receipts'])

    def test_corrupt_state_symlink_and_duplicate_json_fail_closed(self):
        with self.f.node('earth') as node:
            path = node.path
        state = mesh.load(path, mesh.MAX_STATE)
        state['network'] = 'f' * 64
        path.write_bytes(evidence.canonical(mesh.pack_state_storage(state)))
        with self.assertRaisesRegex(ValueError, 'corrupt'):
            self.f.node('earth')
        linked = self.f.root / 'alias'
        linked.symlink_to(self.f.root / 'proxima', target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            mesh.safe_dir(linked)
        path.write_bytes(b'{"format":1,"format":2}')
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            mesh.load(path, 8192)

    def test_opening_unchanged_archive_does_not_rewrite_and_still_authenticates_it(self):
        self.f.rounds()
        with self.f.node('earth') as node:path=node.path
        before=path.read_bytes()
        with patch.object(mesh,'atomic',side_effect=OSError('unexpected archive rewrite')):
            with self.f.node('earth') as node:self.assertEqual(node.path.read_bytes(),before)
        state=mesh.load(path, mesh.MAX_STATE)
        state['adverts'][self.f.identities['proxima']['node_id']]['body']['label']='forged'
        tampered=evidence.canonical(mesh.pack_state_storage(state));path.write_bytes(tampered)
        with self.assertRaisesRegex(ValueError,'signature'):
            self.f.node('earth')
        self.assertEqual(path.read_bytes(),tampered)

    def test_exact_repeated_exchange_syncs_custody_and_sync_failure_preserves_evidence(self):
        self.f.rounds()
        peer=self.f.identities['proxima']['node_id']
        with self.f.node('proxima') as node:bundle=node.exchange(self.f.identities['earth']['node_id'])
        with self.f.node('earth') as node:
            node.receive(bundle,peer)
            before=node.path.read_bytes()
            with patch.object(mesh,'atomic',side_effect=OSError('unexpected archive rewrite')):
                node.receive(bundle,peer)
            self.assertEqual(node.path.read_bytes(),before)
            with patch.object(mesh.os,'fsync',side_effect=OSError('injected retained custody sync failure')):
                with self.assertRaisesRegex(OSError,'sync failure'):node.receive(bundle,peer)
            self.assertEqual(node.path.read_bytes(),before)

    def test_cyclic_advertisements_do_not_loop_or_refund(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            self.assertIsNone(node.route('f' * 64))
            self.assertIsNone(node.route(self.f.identities['andromeda']['node_id'], [self.f.identities['proxima']['node_id']]))
            self.assertFalse(node.status()['payment_authorized'])

    def test_serialized_batch_budget_and_rotation_do_not_starve_messages(self):
        self.f.rounds()
        with self.f.node('earth') as node:
            for i in range(9):
                node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            expected = set(node.state['messages'])
            seen = set()
            peer = self.f.identities['proxima']['node_id']
            full = node.exchange(peer)
            first_size = len(evidence.canonical({**full['body'], 'transits': full['body']['transits'][:1]})) + 512
            with patch.object(mesh, 'MAX_BATCH', first_size + 16):
                for _ in range(9):
                    batch = node.prepare_exchange(peer)
                    self.assertLessEqual(len(evidence.canonical(batch)), mesh.MAX_BATCH)
                    seen.update(mesh.digest(t['packet']) for t in batch['body']['transits'])
            self.assertEqual(seen, expected)

    def test_state_byte_limit_does_not_replace_existing_durable_state(self):
        with self.f.node('earth') as node:
            before = node.path.read_bytes()
            with patch.object(mesh, 'MAX_STATE', len(before)):
                with self.assertRaisesRegex(ValueError, 'capacity'):
                    node.enqueue(self.f.frame(), self.f.identities['andromeda']['node_id'])
            self.assertEqual(node.path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
