"""Actual process telemetry must not turn a missing observation into progress."""
import unittest
import copy
import hashlib
import json
from regional_bft_sustained_campaign import consensus_sample, has_complete_commit_group, retained_resume_heights


class ObservationTests(unittest.TestCase):
    def recovery_origin(self):
        implementation='f'*64
        manifest={'files':[{'path':'tools/regional_bft_sustained_campaign.py','sha256':'a'*64,'size_bytes':1}],
                  'native_implementation':implementation}
        manifest['source_set_sha256']=hashlib.sha256(json.dumps(manifest['files'],sort_keys=True,separators=(',',':')).encode()).hexdigest()
        record={'fixture_only':True,'live_rld':False,'completed':False,'owned_process_cleanup_verified':True,
                'sealed_source_state_unchanged':True,'native_implementation':implementation,
                'runtime_source_set_sha256':manifest['source_set_sha256'],'drill_source_sha256':'a'*64,
                'controller_generated_consensus_messages':0,'controller_carried_payment_proofs':0,'controller_installed_checkpoints':0,
                'conservation_checks':[{'phase':'stopped native stores: complete replay','compatible_prefixes_verified':True,
                    'conserved':True,'replica_heights':{'earth':[12]*4,'proxima':[10,11,10,10],'andromeda':[11,11,12,12]}}]}
        return record,manifest,implementation

    def test_recovery_origin_requires_failed_stopped_cold_evidence_and_exact_source(self):
        record,manifest,implementation=self.recovery_origin()
        self.assertEqual(retained_resume_heights(record,manifest,implementation)['proxima'],[10,11,10,10])
        for field,value in [('completed',True),('owned_process_cleanup_verified',False),('live_rld',True),
                ('sealed_source_state_unchanged',False),('runtime_source_set_sha256','b'*64),
                ('drill_source_sha256','b'*64),('controller_installed_checkpoints',1),('controller_installed_checkpoints',False)]:
            changed=copy.deepcopy(record);changed[field]=value
            with self.assertRaises(ValueError):retained_resume_heights(changed,manifest,implementation)
        changed=copy.deepcopy(manifest);changed['files'][0]['sha256']='b'*64
        with self.assertRaises(ValueError):retained_resume_heights(record,changed,implementation)
        with self.assertRaises(ValueError):retained_resume_heights(record,manifest,'b'*64)

    def test_recovery_cannot_use_live_samples_or_invent_missing_native_heights(self):
        record,manifest,implementation=self.recovery_origin()
        for change in ('live_sample','missing_region','missing_replica','unknown','boolean','outside_bound'):
            candidate=copy.deepcopy(record);cold=candidate['conservation_checks'][-1]
            if change=='live_sample':cold['phase']='failed bounded observation; all evidence retained'
            elif change=='missing_region':cold['replica_heights'].pop('earth')
            elif change=='missing_replica':cold['replica_heights']['proxima'].pop()
            else:cold['replica_heights']['proxima'][0]={'unknown':None,'boolean':True,'outside_bound':25}[change]
            with self.assertRaises(ValueError):retained_resume_heights(candidate,manifest,implementation)

    def test_drain_requires_distinct_current_context_same_round_and_value_commits(self):
        context={'parent_height':9,'parent_block':'current'}
        def vote(key,round_number=0,value='a',phase='Commit',parent=context):
            return {'Vote':{'context':parent,'round':round_number,'value':value,'phase':phase,'approval':{'key':key}}}
        self.assertTrue(has_complete_commit_group([vote('1'),vote('2'),vote('3')],context))
        for messages in ([vote('1'),vote('1'),vote('2')],
                [vote('1'),vote('2'),vote('3',round_number=1)],
                [vote('1'),vote('2'),vote('3',value='b')],
                [vote('1'),vote('2'),vote('3',phase='Prepare')],
                [vote('1'),vote('2'),vote('3',parent={'parent_height':9,'parent_block':'different'})]):
            self.assertFalse(has_complete_commit_group(messages,context))

    def test_native_lock_failure_is_unavailable_instead_of_a_height_or_campaign_error(self):
        # Shape emitted by Service.tick on an actual native lock refusal in the
        # retained eleven-node drill, after certified height-9 progress.
        sample=consensus_sample({'consensus':{'autonomous_signing_enabled':True,
            'diagnostic':'native rejected: regional candidate rejected: lock acquisition failed because the operation would block',
            'independent_bft_qualified':False,'progress_observation_available':False}})
        self.assertFalse(sample['consensus_observation_complete'])
        for field in ('height','round','retained_bft_messages'):self.assertIsNone(sample[field])
        self.assertIn('would block',sample['consensus_diagnostic'])

    def test_missing_and_explicitly_unavailable_samples_cannot_fabricate_progress(self):
        for observed in ({},{'consensus':None},{'consensus':{}},
                {'consensus':{'height':9,'round':0,'retained_messages':108,'progress_observation_available':False}},
                {'consensus':{'height':True,'round':0,'retained_messages':108}}):
            sample=consensus_sample(observed)
            self.assertFalse(sample['consensus_observation_complete']);self.assertIsNone(sample['height'])
        sample=consensus_sample({'consensus':{'height':9,'round':0,'retained_messages':108}})
        self.assertTrue(sample['consensus_observation_complete'])
        self.assertEqual((sample['height'],sample['round'],sample['retained_bft_messages']),(9,0,108))


if __name__=='__main__':unittest.main()
