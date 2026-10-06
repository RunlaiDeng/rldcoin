from pathlib import Path
import ast,copy,hashlib,inspect,json,sys,tempfile,time,unittest
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'));b=r/'tmp/default-relay-20260930';root=b/'unserved-promotion-ordinary-delivery-v3-v12-private-20261006';assert not root.exists();root.mkdir(mode=0o700);start=time.monotonic();deadline=float(sys.argv[1]);assert 0<deadline-start<=49.130756
original=tempfile.TemporaryDirectory
class Retained(original):
 def __init__(self,*args,**kw):
  assert not args and not kw;super().__init__(dir=root,prefix='fresh-ground-');self._finalizer.detach()
 def cleanup(self):pass
import test_interstellar_mesh as tests;tests.tempfile.TemporaryDirectory=Retained;mesh=tests.mesh;sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
# Keep the exact existing signed demotion setup and its original guards; only
# map to a direct source2->destination1 ground analogue and take ordinary tick.
tree=ast.parse((r/'tools/test_interstellar_mesh.py').read_text());cls=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='MeshTests');method=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=='test_promoted_latest_waiter_keeps_priority_until_prepared');text=ast.unparse(method)
text=text.replace("self.f.node('earth')","self.f.node('proxima')").replace("self.f.identities['proxima']['node_id']","self.f.identities['earth']['node_id']").replace("self.f.identities['andromeda']['node_id']","self.f.identities['earth']['node_id']")
needle='        bundle = node.prepare_exchange(peer)';assert text.count(needle)==1
replacement="""        # Actual tick atomically prepares and writes the ordinary exchange;
        # no controller-selected retry/suppression or manual receive is used.
        outbox = node.contacts[peer]['outbox']
        prior_paths = set(outbox.glob('*.json'))
        report = node.tick()
        self.assertFalse(report['errors'])
        new_paths = set(outbox.glob('*.json')) - prior_paths
        self.assertEqual(len(new_paths), 1)
        exchange_path = next(iter(new_paths))
        bundle = mesh.load(exchange_path, mesh.MAX_BATCH)
        self.assertEqual(exchange_path.stem, mesh.digest(bundle))
        body = mesh.verify(bundle, 'exchange', tests.NETWORK)
        self.assertEqual((body['node_id'], body['to']), (node.id, peer))
        carried = next(t for t in body['transits'] if mesh.digest(t['packet']) == target)
        self.assertEqual(carried['packet'], original[target]['packet'])
        self.assertEqual(carried['routing'], original[target]['routing'])
        self.assertEqual(len(carried['hops']), 1)
        raw = mesh.transit_check(carried, tests.NETWORK)[1]
        self._delivery = dict(target_packet_id=target, exchange_sha256=sha(exchange_path),
                              original_frame_sha256=hashlib.sha256(raw).hexdigest(),
                              ordinary_source_tick_count=1)
        self._target = target
        self._original_packet = copy.deepcopy(original[target]['packet'])
        self._original_routing = copy.deepcopy(original[target]['routing'])
        self._original_frame = raw"""
text=text.replace(needle,replacement)
text += """
    # One destination ordinary tick only. No repeat on missing delivery.
    self.f.rounds(1, names=['earth'])
    with mesh._verified_transits_lock:
        mesh._verified_transits.clear()
    with mesh._carriage_position_lock:
        mesh._carriage_positions.clear()
        mesh._carriage_position_bytes = 0
    with self.f.node('earth') as node:
        transit = node.transit(self._target)
        packet, raw, visited = mesh.transit_check(transit, tests.NETWORK)
        self.assertEqual(transit['packet'], self._original_packet)
        self.assertEqual(transit['routing'], self._original_routing)
        self.assertEqual(raw, self._original_frame)
        self.assertEqual(packet['destination'], node.id)
        self.assertEqual(len(transit['hops']), 1)
        receipt = node.receipts()[self._target]
        self.assertEqual(mesh.receipt_check(receipt, tests.NETWORK), self._target)
        mesh.receipt_matches(receipt, transit)
        self.assertEqual(receipt['body']['node_id'], node.id)
        export = self.f.root/'destination-original.frame.json'
        node.export_received(self._target, export)
        self.assertEqual(export.read_bytes(), self._original_frame)
        self.assertFalse(node.status()['payment_authorized'])
        self._delivery.update(destination_ordinary_tick_count=1, source_signed_packet_routing_bytes_exact=True,
                              complete_hop_and_destination_receipt_authenticated=True,
                              destination_original_frame_export_sha256=sha(export),
                              destination_cold_open_with_transit_witnesses_cleared=True,
                              ground_source2_destination1_role_analogue=True,
                              original_failed_Native_Proposal_copied_or_signed=False,
                              Native_Proposal_inner_signature_or_ledger_maturity_qualified=False)
    (self.f.root/'ordinary-delivery-reference.json').write_text(json.dumps(self._delivery, indent=2)+'\\n')
"""
namespace=dict(vars(tests));namespace['sha']=sha;namespace['tests']=tests;exec(compile(text,'fresh-single-path-ordinary-delivery','exec'),namespace)
DeliveryCase=type('DeliveryCase',(tests.MeshTests,),{'test_promoted_latest_waiter_keeps_priority_until_prepared':namespace['test_promoted_latest_waiter_keeps_priority_until_prepared']});case=DeliveryCase('test_promoted_latest_waiter_keeps_priority_until_prepared');result=unittest.TextTestRunner(verbosity=2,failfast=True).run(unittest.TestSuite([case]));assert time.monotonic()<deadline
output=dict(completed=result.wasSuccessful(),tests_run=result.testsRun,failed_tests=[str(t) for t,_ in result.failures],error_tests=[str(t) for t,_ in result.errors],duration_seconds=round(time.monotonic()-start,6),current_profile=mesh.TRANSIT_SCHEDULER,ordinary_delivery=getattr(case,'_delivery',None),old_signed_V11_failure_reused_not_rerun=True,previous_ten_guard_results_reused_source_unchanged=True,original_pending_pair_full4_auth_atomic_floor_cold_checked_on_this_same_target=result.wasSuccessful(),fresh_ground_only=True,old_failed_fixture_reopens=0,actual_Native_Runtime_TLS_calls=0,new180_allocated=0,new600_allocated=0,full_fault_qualified=False,whole_goal_completed=False)
print('bounded-related-result '+json.dumps(output));raise SystemExit(0 if result.wasSuccessful() else 1)
