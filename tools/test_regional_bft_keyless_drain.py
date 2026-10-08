"""Native stop-observation counter and pure guards; never full fault acceptance."""
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest

from regional_bft_keyless_drain import current_commits, reports_drained


class DrainReportTests(unittest.TestCase):
    def fixture(self):
        context=dict(currency='1'*64,region='2'*64,epoch='3'*64,previous=None,
                     parent_height=0,parent_block='4'*64,parent_state='5'*64)
        bindings={('earth',n):dict(key=f'{n+1:064x}',head=f'{n+5:064x}') for n in range(4)}
        heights=dict.fromkeys(bindings,0)
        reports={slot:current_commits(context,[],row['key'],row['head']) for slot,row in bindings.items()}
        return context,bindings,heights,reports

    def ready(self,bindings,heights,reports):
        return reports_drained(reports,bindings,heights,'1'*64,{'earth':'2'*64})

    def test_same_height_is_insufficient_for_three_actual_distinct_committers(self):
        context,bindings,heights,reports=self.fixture()
        for slot,row in list(bindings.items())[:3]:
            message={'Vote':dict(phase='Commit',context=context,round=0,value='6'*64,approval={'key':row['key']})}
            reports[slot]=current_commits(context,[message],row['key'],row['head'])
        self.assertFalse(self.ready(bindings,heights,reports))
        reports[('earth',2)]=current_commits(context,[],bindings['earth',2]['key'],bindings['earth',2]['head'])
        self.assertTrue(self.ready(bindings,heights,reports))

    def test_missing_changed_caller_context_or_height_cannot_trigger_stop(self):
        for why in ('missing','caller','height','context'):
            context,bindings,heights,reports=self.fixture()
            if why=='missing':reports.pop(('earth',0))
            elif why=='caller':reports['earth',0]['caller_head']='9'*64
            elif why=='height':heights['earth',0]=1
            else:reports['earth',0]['context']['parent_state']='9'*64
            with self.subTest(why=why):self.assertFalse(self.ready(bindings,heights,reports))

    def test_bad_authority_domain_vote_owner_duplicate_and_round_refuse(self):
        for why in ('signing','freshness','domain','owner','duplicate','round','shared-key'):
            context,bindings,heights,reports=self.fixture();row=reports['earth',0]
            if why=='signing':row['signing_authority']=True
            elif why=='freshness':row['independent_freshness_qualified']=True
            elif why=='domain':row['context']['currency']='9'*64
            elif why=='shared-key':bindings['earth',1]['key']=bindings['earth',0]['key']
            else:
                vote=dict(round=0,value='6'*64,key=bindings['earth',0]['key']);row['commits']=[vote]
                if why=='owner':vote['key']=bindings['earth',1]['key']
                elif why=='duplicate':row['commits'].append(dict(vote))
                else:vote['round']=True
            with self.subTest(why=why),self.assertRaises(ValueError):self.ready(bindings,heights,reports)

    def test_only_own_current_native_commit_votes_are_summarized_without_mutation(self):
        context,bindings,_,_=self.fixture();key=bindings['earth',0]['key'];head=bindings['earth',0]['head']
        message={'Vote':dict(phase='Commit',context=context,round=1,value='6'*64,approval={'key':key})}
        old=copy.deepcopy(message);prior=copy.deepcopy(message);prior['Vote']['context']['parent_height']=1
        row=current_commits(context,[prior,message],key,head)
        self.assertEqual(row['commits'],[dict(round=1,value='6'*64,key=key)]);self.assertEqual(message,old)
        bad=copy.deepcopy(message);bad['Vote']['approval']['key']=bindings['earth',1]['key']
        with self.assertRaises(ValueError):current_commits(context,[bad],key,head)


class RuntimeDrainGuards(unittest.TestCase):
    def runtime(self):
        from test_regional_bft_loop_observation import LoopObservationTests
        from regional_bft_node import FORMAT
        r,value,calls=LoopObservationTests().runtime()
        r.format=FORMAT;r.joint=None;r.key_file=None;r.key='4'*64
        value['format']='RLD-BFT-LOOP-RETAINED-OBSERVATION-V1';value['retained_messages']=[]
        return r,value,calls

    def test_exact_retained_domain_and_caller_required_before_summary_or_height_update(self):
        for why in ('format','missing','head','binding','authority','messages','owner','round'):
            r,value,calls=self.runtime();value['native']['context']['parent_height']=11
            if why=='format':value['format']='RLD-BFT-LOOP-OBSERVATION-V1'
            elif why=='missing':value.pop('retained_messages')
            elif why=='head':value['signer']['head']='wrong'
            elif why=='binding':value['signer']['binding']='wrong'
            elif why=='authority':value['signing_authority']=True
            elif why=='messages':value['retained_messages']={}
            else:
                vote=dict(phase='Commit',context=value['native']['context'],round=0,value='6'*64,
                          approval=dict(key=r.key))
                if why=='owner':vote['approval']['key']='5'*64
                else:vote['round']=True
                value['retained_messages']=[dict(Vote=vote)]
            with self.subTest(why=why),self.assertRaises(ValueError):r.loop_observation()
            self.assertEqual(len(calls),1);self.assertEqual(r.state['height'],10)
            self.assertIsNone(r._keyless_drain_observation)

    def test_fresh_native_refusal_has_no_previous_summary_fallback(self):
        r,_,calls=self.runtime();r.loop_observation();self.assertIsNotNone(r._keyless_drain_observation)
        def refuse(*args):raise ValueError('fresh Native refusal')
        r.native.call=refuse
        with self.assertRaisesRegex(ValueError,'fresh Native refusal'):r.loop_observation()
        self.assertIsNone(r._keyless_drain_observation);self.assertEqual(len(calls),1)


class NativeDrainObservationTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('RLD_DRAIN_VISIBILITY_FIXTURE') and os.environ.get('RLD_CONTACT_BINARY'),
                         'requires successful source-bound Native counter stores')
    def test_real_native_current_signer_votes_prevent_early_stop_without_key_or_mutation(self):
        from regional_bft_node import Runtime, FORMAT
        from regional_bft_retention import Messages
        from regional_contact_node import Native
        from regional_contact_campaign import public
        from regional_paged_fault_scope import inventory
        root=Path(os.environ['RLD_DRAIN_VISIBILITY_FIXTURE']).resolve()
        binary=Path(os.environ['RLD_CONTACT_BINARY']).resolve()
        observations=json.loads((root/'actual-Native-current-Commit-observation.json').read_text())
        context=observations['context'];reports={};bindings={};heights={};commands=[]
        class Recorded(Native):
            def call(self,*args,**kw):commands.append(args);return super().call(*args,**kw)
        before={str(p):inventory(p) for n in range(4) for p in
                (root/f'earth-{n}',root/f'earth-{n}-signer')}
        callers={str(root/f'fixture-caller-earth-{n}.json'):
                 (root/f'fixture-caller-earth-{n}.json').read_bytes() for n in range(4)}
        for n in range(4):
            caller=json.loads(callers[str(root/f'fixture-caller-earth-{n}.json')]);r=Runtime.__new__(Runtime)
            r.format=FORMAT;r.joint=None;r.key_file=None;r.stop_height=1;r.key=caller['binding']['key'];r.region=context['region']
            r.head=caller;r.signing_binding=caller['binding'];r.signer=root/f'earth-{n}-signer'
            r.state=dict(height=0,tip=context['parent_block'],messages=Messages())
            r.native=Recorded(binary,root/f'earth-{n}',public(1),context['currency'])
            actual,status=r.loop_observation();self.assertEqual(actual,context)
            report=r.report(actual,0,status,True);reports['earth',n]=report['native_keyless_drain']
            self.assertFalse(report['autonomous_signing_enabled'])
            bindings['earth',n]=dict(key=r.key,head=caller['head']);heights['earth',n]=0
            self.assertEqual(commands[-1],('bft-loop-status','--signer-dir',r.signer,
                                          '--expected-head',caller['head'],'--include-retained-messages'))
            self.assertEqual(report['native_keyless_drain']['commits'],[] if n==3 else
                             [dict(round=0,value=observations['actual_retained_signed_messages'][0]['Vote']['value'],key=r.key)])
        self.assertFalse(reports_drained(reports,bindings,heights,context['currency'],{'earth':context['region']}))
        self.assertEqual({str(p):inventory(Path(p)) for p in before},before)
        self.assertEqual({p:Path(p).read_bytes() for p in callers},callers)
        self.assertEqual(len(commands),4)


if __name__=='__main__':unittest.main()
