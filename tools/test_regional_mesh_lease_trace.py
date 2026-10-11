"""Wall-time observation preserves lease refusal, bounds and actual TLS custody."""
import tempfile
import threading
import unittest
from unittest.mock import patch

import interstellar_mesh_cost as costs_module
import interstellar_tcp as tcp
from interstellar_mesh_cost import MeshCosts,MAX_COUNT,MAX_SECONDS
from regional_contact_trace import ContactTrace,TraceCursor,MAX_EVENTS
import test_interstellar_mesh_cost as lease_fixture
from test_interstellar_tcp import Fixture,NETWORK


class MeshLeaseTraceTests(unittest.TestCase):
    def trace(self):
        trace=ContactTrace();trace.bind(NETWORK,'b'*64)
        return trace

    def lease(self,trace,**kwargs):
        with patch.object(lease_fixture,'MeshCosts',lambda:MeshCosts(contact_trace=trace)):
            return lease_fixture.LeaseCostsTests().run_path(**kwargs)

    def test_exact_existing_durations_preserve_open_acquire_hold_overlap(self):
        trace=self.trace()
        server,order,error,duration=self.lease(trace)
        self.assertIsNone(error)
        self.assertEqual(order,['open','body','close'])
        rows=trace.snapshot()['events']
        self.assertEqual([x['cost_stage'] for x in rows],['purpose','open','acquire','hold'])
        self.assertEqual([x['duration_microseconds'] for x in rows],[0,350000,350000,520000])
        self.assertTrue(all(x['cost_success'] and x['cost_call']==1 for x in rows))
        self.assertEqual({x['worker_id'] for x in rows},{threading.get_ident()})
        self.assertFalse(trace.snapshot()['authority'])
        self.assertIsNone(server.local_mesh_owner)

    def test_original_refusals_and_ownership_match_without_trace(self):
        for kwargs in ({},{'failure':'open'},{'failure':'body'},{'failure':'close'},
                       {'busy':True},{'ordinary':False}):
            with self.subTest(kwargs=kwargs):
                trace=self.trace();actual=self.lease(trace,**kwargs)
                reference=lease_fixture.LeaseCostsTests().run_path(**kwargs)
                self.assertEqual(actual[1],reference[1])
                self.assertEqual(type(actual[2]),type(reference[2]))
                self.assertEqual(str(actual[2]),str(reference[2]))
                self.assertEqual(actual[3],reference[3])
                self.assertEqual(actual[0].mesh_costs.snapshot(),reference[0].mesh_costs.snapshot())
                if kwargs.get('busy'):self.assertIsNotNone(actual[0].local_mesh_owner)
                else:self.assertIsNone(actual[0].local_mesh_owner)
                rows=trace.snapshot()['events']
                if kwargs.get('busy'):
                    self.assertEqual([x['cost_stage'] for x in rows],['purpose','acquire'])
                    self.assertFalse(rows[-1]['cost_success'])
                if kwargs.get('failure')=='body':self.assertTrue(rows[-1]['cost_success'])
                if kwargs.get('failure')=='close':self.assertFalse(rows[-1]['cost_success'])

    def test_refused_observer_cannot_change_lease_outcome_or_aggregate(self):
        trace=self.trace()
        with patch.object(trace,'event',side_effect=OSError('diagnostic refused')):
            actual=self.lease(trace)
        reference=lease_fixture.LeaseCostsTests().run_path()
        self.assertEqual(actual[1:],reference[1:])
        self.assertEqual(actual[0].mesh_costs.snapshot(),reference[0].mesh_costs.snapshot())
        self.assertEqual(trace.snapshot()['rejected_events'],4)
        self.assertFalse(TraceCursor(NETWORK,'b'*64).drain(trace.snapshot())['this_interval_complete'])

    def test_saturation_invalid_metadata_and_eviction_keep_fixed_bounds(self):
        trace=self.trace();costs=MeshCosts(contact_trace=trace)
        costs.rows['receive','hold']['calls']=MAX_COUNT
        costs.record('receive','hold',MAX_SECONDS*2,False)
        row=trace.snapshot()['events'][0]
        self.assertEqual(row['duration_microseconds'],int(MAX_SECONDS*1e6))
        self.assertEqual(row['cost_call'],MAX_COUNT)
        self.assertFalse(row['cost_success'])
        for role,stage,duration in [('private/path','open',1),('receive','secret',1),
                                    ('receive','open',float('nan'))]:
            costs.record(role,stage,duration,True)
        self.assertEqual(trace.snapshot()['sequence'],1)
        for fields in ({'cost_role':'secret'},{'cost_stage':'secret'},
                       {'duration_microseconds':True},{'worker_id':2**63}):
            trace.event('mesh_lease_cost',**fields)
        self.assertEqual(trace.snapshot()['rejected_events'],4)
        for _ in range(MAX_EVENTS):costs.record('receive','hold',.1,True)
        delta=TraceCursor(NETWORK,'b'*64).drain(trace.snapshot())
        self.assertEqual(delta['missed_events'],1)
        self.assertFalse(delta['this_interval_complete'])
        self.assertEqual(MeshCosts().snapshot()['rows']['receive']['hold']['calls'],0)

    def actual_fixture(self):
        temporary=tempfile.TemporaryDirectory(prefix='rld-lease-trace-')
        self.addCleanup(temporary.cleanup)
        original=tcp.Server
        def server(*args,**kwargs):
            trace=ContactTrace()
            result=original(*args,contact_trace=trace,**kwargs)
            trace.bind(result.network,result.id)
            return result
        with patch.object(tcp,'Server',side_effect=server):
            fixture=Fixture(temporary.name,names=('earth','proxima'))
        self.addCleanup(fixture.close)
        return fixture

    def deliver(self,fixture):
        with fixture.node('earth') as node:packet=node.enqueue(fixture.frame(),fixture.ids['proxima'])
        errors=[]
        def rounds():
            try:fixture.rounds(2)
            except BaseException as error:errors.append(error)
        worker=threading.Thread(target=rounds)
        for server in fixture.servers.values():server.claim_outbound(worker)
        worker.start();worker.join(10)
        self.assertFalse(worker.is_alive(),'original bounded outgoing worker did not finish')
        for server in fixture.servers.values():server.release_outbound(worker)
        if errors:raise errors[0]
        with fixture.node('proxima') as node:
            self.assertIn(packet,node.receipts())
            self.assertFalse(node.status()['payment_authorized'])

    def test_actual_pinned_TLS_uses_constructor_observer_and_complete_peer_boundaries(self):
        fixture=self.actual_fixture();self.deliver(fixture)
        server=fixture.servers['earth'];trace=server.contact_trace
        self.assertIs(server.mesh_costs.contact_trace,trace)
        delta=TraceCursor(NETWORK,fixture.ids['earth']).drain(trace.snapshot())
        self.assertTrue(delta['this_interval_complete'])
        rows=delta['events']
        starts=[(x['peer'],x['attempt'],x['worker_id']) for x in rows if x['stage']=='outbound_peer_started']
        ends=[(x['peer'],x['attempt'],x['worker_id']) for x in rows if x['stage']=='outbound_peer_finished']
        self.assertEqual(starts,ends);self.assertEqual(len(starts),2)
        stages={x['cost_stage'] for x in rows if x['stage']=='mesh_lease_cost' and x['cost_role']=='tcp_outbound'}
        self.assertEqual(stages,{'open','acquire','hold'})

    def test_actual_TLS_diagnostic_rejection_preserves_durable_delivery(self):
        fixture=self.actual_fixture();trace=fixture.servers['earth'].contact_trace
        original=trace.event
        def event(stage,*args,**kwargs):
            if stage in ('mesh_lease_cost','outbound_peer_started','outbound_peer_finished'):
                raise OSError('diagnostic row refused')
            return original(stage,*args,**kwargs)
        with patch.object(trace,'event',side_effect=event):self.deliver(fixture)
        self.assertGreater(trace.snapshot()['rejected_events'],0)
        self.assertFalse(TraceCursor(NETWORK,fixture.ids['earth']).drain(trace.snapshot())['this_interval_complete'])

    def test_refused_connection_finishes_attempt_without_custody_claim(self):
        fixture=self.actual_fixture();fixture.stop('proxima')
        server=fixture.servers['earth'];result=server.tick()
        self.assertTrue(result['errors'])
        rows=TraceCursor(NETWORK,fixture.ids['earth']).drain(server.contact_trace.snapshot())['events']
        starts=[(x['peer'],x['attempt']) for x in rows if x['stage']=='outbound_peer_started']
        ends=[(x['peer'],x['attempt']) for x in rows if x['stage']=='outbound_peer_finished']
        self.assertEqual(starts,ends);self.assertEqual(len(starts),1)
        self.assertIn('contact_failed',[x['stage'] for x in rows])
        self.assertNotIn('peer_custody_authenticated',[x['stage'] for x in rows])


if __name__=='__main__':unittest.main()
