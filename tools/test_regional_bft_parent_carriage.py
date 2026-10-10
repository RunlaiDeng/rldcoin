"""No-value extra scheduling filters/models, never Native ledger qualification.

Deterministic published test seeds sign metadata only. These deliberately empty
snapshot block arrays cannot supply Native finality. The Runtime models assert
the existing authenticated/cold/durable boundary before scheduling; actual full
envelope and chain authentication is tested separately by the native fixture.
"""
import copy
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_retention import Messages
from regional_bft_node import (Runtime,ORIGIN_RUNTIME_FORMAT,FORMAT,ORIGIN_NETWORK,
    parent_carriage_pair,carriage_batch,carriage_frontier,current_finalized_hint)
import test_regional_bft_carriage_frontier as publication_fixture

FIELDS=('currency','region','height','block','state','previous','epoch')
CONTEXT_FIELDS=('currency','region','epoch','previous','parent_height','parent_block','parent_state')
DOMAIN=b'RLD-REGIONAL-FIXTURE-V1:'
encode=lambda v:wire.json.dumps(v,separators=(',',':'),ensure_ascii=False).encode()

def fixture(height=3,epoch='3'*64,certificate_round=0):
    seeds=[Ed25519PrivateKey.from_private_bytes(bytes([n])*32) for n in range(2,6)]
    secrets={s.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex():s for s in seeds}
    keys=sorted(secrets);peers={k:format(n+1,'064x') for n,k in enumerate(keys)}
    parent=dict(currency='1'*64,region='2'*64,epoch=epoch,previous='4'*64,
                parent_height=height-1,parent_block='5'*64,parent_state='6'*64)
    statement=dict(currency=parent['currency'],region=parent['region'],height=height,
                   block='7'*64,state='8'*64,previous=parent['previous'],epoch=epoch)
    value=hashlib.sha256(DOMAIN+b'unanimous-checkpoint\0'+encode({k:statement[k] for k in FIELDS})).hexdigest()
    quorums={}
    for name,phase in (('prepared','Prepare'),('committed','Commit')):
        votes=[]
        for key in keys[:3]:
            data=DOMAIN+b'bft-vote-v1\0'+encode([{k:parent[k] for k in CONTEXT_FIELDS},certificate_round,value,phase,key])
            votes.append(dict(context=copy.deepcopy(parent),round=certificate_round,value=value,phase=phase,
                              approval=dict(key=key,signature=secrets[key].sign(data).hex())))
        quorums[name]=dict(context=copy.deepcopy(parent),round=certificate_round,value=value,phase=phase,votes=votes)
    snapshot=dict(base=statement['previous'],statement=statement,approvals=[],blocks=[],epochs=[],bft=quorums)
    context={k:statement[k] for k in ('currency','region','epoch')}
    context.update(previous=value,parent_height=height,parent_block=statement['block'],parent_state=statement['state'])
    body={'Finalized':snapshot};ident=mesh.digest(body)
    envelope=dict(format=ORIGIN_NETWORK,currency=context['currency'],region=context['region'],body=body,evidence={'snapshots':[]},origins=[])
    messages=Messages().append(ident,envelope,value,True)
    history={'Signed':{'Vote':dict(context=parent,round=certificate_round,value=value,phase='Commit',approval={'key':keys[0],'signature':'model-only-no-authority'})}}
    history_id=mesh.digest(history)
    messages=messages.append(history_id,dict(envelope,body=history),value,True)
    pending=[(messages.content(i),i,p) for i in sorted(messages) for p in sorted(peers.values())]
    return messages,pending,context,peers,ident,history_id,envelope

class ParentCarriageTests(unittest.TestCase):
    def choose(self,m,p,c,peers,r=0,cursor=8,position=(None,None)):
        priority=parent_carriage_pair(m,p,c,peers,r)
        selected=carriage_batch(m,p,c['parent_height'],cursor,prepare_first=True,
                               proposal_context=c,class_position=position,parent_pair=priority)
        return selected,priority

    def test_complete_parent_replaces_one_current_place_without_changing_history(self):
        m,p,c,peers,i,h,_=fixture()
        old=carriage_batch(m,p,3,8,prepare_first=True,proposal_context=c,class_position=(None,None))
        selected,priority=self.choose(m,p,c,peers)
        self.assertIsNotNone(priority);self.assertIn(priority,selected)
        self.assertEqual(priority[2],peers[sorted(peers)[3]])
        self.assertEqual([x for x in selected if x[1]==h],[x for x in old if x[1]==h])
        self.assertEqual(sum(x[1]==i for x in selected),2)
        self.assertEqual(len(selected),4);self.assertEqual(len(set(selected)),4)

    def test_leader_uses_new_parent_height_and_current_round_not_certificate_round(self):
        for height in (1,2,3,4,13):
            m,p,c,peers,*_=fixture(height=height,certificate_round=9)
            for r in (0,1,2,3,7,31):
                with self.subTest(height=height,round=r):
                    _,priority=self.choose(m,p,c,peers,r)
                    self.assertIsNotNone(priority)
                    self.assertEqual(priority[2],peers[sorted(peers)[(height+r)%4]])
        for r in (None,True,-1,32,'0'):
            self.assertIsNone(parent_carriage_pair(m,p,c,peers,r))

    def test_every_native_context_component_and_value_must_match(self):
        m,p,c,peers,*_=fixture()
        for field in CONTEXT_FIELDS:
            changed=dict(c);changed[field]=c[field]+1 if field=='parent_height' else 'a'*64
            self.assertIsNone(parent_carriage_pair(m,p,changed,peers,0),field)
        for context in (None,{},dict(c,untrusted='extra'),dict(c,parent_height=True)):
            self.assertIsNone(parent_carriage_pair(m,p,context,peers,0))
        i=next(i for i in m if 'Finalized' in m.record(i)['body'])
        bad=Messages().append(i,m.envelope(i),'a'*64,True)
        self.assertIsNone(parent_carriage_pair(bad,p,c,peers,0))

    def test_epoch_change_requires_matching_complete_certificate_and_admitted_roles(self):
        m,p,c,peers,*_=fixture(epoch='a'*64)
        self.assertIsNone(parent_carriage_pair(m,p,dict(c,epoch='b'*64),peers,0))
        replacement=dict(peers);k=sorted(peers)[0];replacement['f'*64]=replacement.pop(k)
        self.assertIsNone(parent_carriage_pair(m,p,c,replacement,0))
        newer,p2,c2,roles,*_=fixture(height=4,epoch='b'*64)
        _,priority=self.choose(newer,p2,c2,roles,r=2)
        self.assertEqual(priority[2],roles[sorted(roles)[2]])

    def test_invalid_quorum_signature_and_conflicting_checkpoint_supply_no_priority(self):
        m,p,c,peers,i,h,envelope=fixture()
        for change in ('forged','two','duplicate','unordered','mixed','conflict','base'):
            e=copy.deepcopy(envelope);s=e['body']['Finalized'];q=s['bft']['committed'];vote=q['votes'][0]
            if change=='forged':vote['approval']['signature']='0'*128
            elif change=='two':q['votes'].pop()
            elif change=='duplicate':q['votes'][1]=copy.deepcopy(q['votes'][0])
            elif change=='unordered':q['votes'].reverse()
            elif change=='mixed':vote['round']+=1
            elif change=='conflict':s['statement']['state']='a'*64
            else:s['base']='a'*64
            j=mesh.digest(e['body']);bad=Messages().append(j,e,c['previous'],True)
            copies=[(bad.content(j),j,peer) for peer in peers.values()]
            before=bad.payload(j)
            self.assertIsNone(parent_carriage_pair(bad,copies,c,peers,0),change)
            self.assertEqual(before,bad.payload(j))
            combined=m.append(j,e,c['previous'],True)
            self.assertEqual(parent_carriage_pair(combined,p+copies,c,peers,0)[1],i)

    def test_remote_wrong_domain_content_and_misconfigured_roles_do_not_prioritize(self):
        m,p,c,peers,i,h,e=fixture()
        remote=Messages().append(i,e,c['previous'],False)
        self.assertIsNone(parent_carriage_pair(remote,p,c,peers,0))
        for field,value in (('format','RLD-REGIONAL-BFT-NETWORK-V2'),('currency','a'*64),('region','a'*64)):
            changed=dict(e,**{field:value})
            if field=='format':changed.pop('origins')
            wrong=Messages().append(i,changed,c['previous'],True)
            self.assertIsNone(parent_carriage_pair(wrong,p,c,peers,0))
        wrong=[('0'*64,ident,peer) for _,ident,peer in p]
        self.assertIsNone(parent_carriage_pair(m,wrong,c,peers,0))
        duplicate={k:'a'*64 for k in peers}
        for roles in ({},dict(list(peers.items())[:3]),duplicate,{'bad':None,**dict(list(peers.items())[1:])}):
            self.assertIsNone(parent_carriage_pair(m,p,c,roles,0))

    def test_retained_pair_reconnect_cold_bytes_and_round_role_change(self):
        m,p,c,peers,i,h,e=fixture();selected,priority=self.choose(m,p,c,peers)
        retained={priority};waiting=[x for x in p if x not in retained]
        self.assertIsNone(parent_carriage_pair(m,waiting,c,peers,0))
        records,snapshots=m.packed();cold=Messages.unpack(records,snapshots)
        self.assertIsNone(parent_carriage_pair(cold,waiting,c,peers,None))
        self.assertIsNone(parent_carriage_pair(cold,waiting,c,peers,0))
        other=parent_carriage_pair(cold,waiting,c,peers,1)
        self.assertEqual(other[2],peers[sorted(peers)[0]])
        # Reconnecting does not erase retained evidence. If the exact enqueue
        # never became durable, the same original pending pair is selected again.
        self.assertEqual(parent_carriage_pair(cold,p,c,peers,0),priority)
        self.assertEqual(cold.payload(i),m.payload(i))

    def test_other_current_peers_and_all_history_keep_bounded_fairness(self):
        m,p,c,peers,i,h,e=fixture();initial=set(p);retained=set();position=(None,None)
        for step in range(12):
            waiting=[pair for pair in p if pair not in retained]
            chosen,priority=self.choose(m,waiting,c,peers,cursor=step*4,position=position)
            self.assertLessEqual(len(chosen),4);self.assertEqual(len(chosen),len(set(chosen)))
            if any(x[1]==i for x in waiting) and any(x[1]==h for x in waiting):
                self.assertGreaterEqual(sum(x[1]==h for x in chosen),min(2,sum(x[1]==h for x in waiting)))
            retained.update(chosen);position=carriage_frontier(m,chosen,3,position)
        self.assertEqual(initial,retained)
        # Repeated unchanged invocations cannot retain a new priority flag;
        # original recipient inventory decides completion, even after restart.
        self.assertEqual(self.choose(m,[],c,peers)[0],[])

    def test_missing_authentication_or_wrong_profile_never_installs_parent_pair(self):
        original=publication_fixture.RuntimeFrontierBoundaryTests()
        for modify in (lambda r:setattr(r,'_retained_native_authenticated',False),
                       lambda r:setattr(r,'format',FORMAT)):
            r=original.runtime();modify(r)
            with patch('regional_bft_node.commit_carriage_frames',return_value=()), \
                 patch('regional_bft_node.parent_carriage_pair',side_effect=AssertionError('must not inspect parent')), \
                 patch('regional_bft_node.carriage_batch',wraps=carriage_batch) as select:
                r.broadcast()
                self.assertIsNone(select.call_args.kwargs['parent_pair'])

    def test_finalization_round_zero_is_after_native_install_retention_and_observation(self):
        for fail in (None,'finalize','retain','observe'):
            r=Runtime.__new__(Runtime);r.format=ORIGIN_RUNTIME_FORMAT;r.joint=None;r._carriage_round=None
            calls=[]
            def event(name,result=None):
                calls.append(name)
                if fail==name:raise OSError('model original durable refusal')
                return result
            r.with_json=lambda *_:event('finalize')
            r.retain_local_body=lambda *_:event('retain')
            r.observe=lambda:event('observe',{'parent_height':3})
            r.broadcast=lambda:event('broadcast')
            r.report=lambda *_a,**_k:None;r.stop_height=3
            r.state={'height':3}
            if fail:
                with self.assertRaises(OSError):r._finish_local_finalization({}, {'parent_height':2},9,'modeled')
                self.assertIsNone(r._carriage_round)
                self.assertNotIn('broadcast',calls)
            else:
                r._finish_local_finalization({}, {'parent_height':2},9,'modeled')
                self.assertEqual(calls,['finalize','retain','observe','broadcast'])
                self.assertEqual(r._carriage_round,0)

    def test_publication_failure_does_not_suppress_the_same_pending_parent(self):
        m,p,c,peers,*_=fixture();first=parent_carriage_pair(m,p,c,peers,0)
        for boundary in ('open','enqueue','close','save'):
            fixture_model=publication_fixture.RuntimeFrontierBoundaryTests()
            r=fixture_model.runtime();r.failure=boundary
            with patch('regional_bft_node.commit_carriage_frames',return_value=()), \
                 patch('regional_bft_node.parent_carriage_pair',return_value=first):
                with self.assertRaises(OSError):r.broadcast()
            self.assertEqual(parent_carriage_pair(m,p,c,peers,0),first)

if __name__=='__main__':unittest.main()
