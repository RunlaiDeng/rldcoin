"""Selection metadata equivalence; synthetic records grant no native rights."""
import copy
from pathlib import Path
import tempfile
from types import MappingProxyType, SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_query_index as index
from regional_bft_retention import Messages, pack_state
from regional_bft_node import Runtime, signed_body

CONTEXT = dict(currency='a'*64, region='b'*64, epoch='c'*64, previous='d'*64,
               parent_height=10, parent_block='e'*64)
VALUE = 'f'*64
SCOPE = dict(format='fixture', binding=dict(currency='a'*64, region='b'*64, key='key'))


def append(messages, kind, rnd=0, phase=None, key='key-0', variant=0,
           value=VALUE, local=False, context=CONTEXT, epoch=False, evidence=None):
    if kind == 'Proposal':
        p = dict(round=rnd, leader=dict(key=key), snapshot=dict(statement=dict(
            currency=context['currency'], region=context['region'], epoch=context['epoch'],
            previous=context['previous'], height=context['parent_height']+1), extra=dict(items=[variant])))
    else:
        p = dict(context=copy.deepcopy(context), round=rnd,
                 approval=dict(key=key, signature=str(variant)))
        if phase is not None:p['phase'] = phase
    message = {kind:p}
    body = {'EpochSigned':dict(message=message, epochs=[dict(variant=variant)])} if epoch else {'Signed':message}
    env = dict(format='RLD-REGIONAL-BFT-NETWORK-V2', currency=CONTEXT['currency'],
               region=CONTEXT['region'], body=body, evidence=dict(snapshots=evidence or []))
    return messages.append(mesh.digest(body), env, value, local)


def probe(messages, ready=False):
    p = SimpleNamespace(state=dict(messages=messages, binding=SCOPE['binding']),
        format='fixture', native=SimpleNamespace(currency=CONTEXT['currency'], authority='1'*64,
        ledger=Path('/unused/synthetic-ledger')), _signed_query_ready=ready, _signed_query_index=None)
    p.signed = lambda *a,**kw: Runtime.signed(p,*a,**kw)
    return p


def query(previous, messages, context=CONTEXT, scope=SCOPE, rnd=0, kind='Vote', phase=None, value=None):
    return index.lookup(previous,messages,context,scope,rnd,kind,phase,value,signed_body)


class QueryIndexTests(unittest.TestCase):
    def setUp(self):
        self.messages=Messages()
        for rnd in (0,1,31):
            for epoch in (False,True):
                self.messages=append(self.messages,'Proposal',rnd,variant=int(epoch),epoch=epoch)
                for phase in ('Prepare','Commit'):
                    for key in ('key-2','key-0','key-1'):
                        self.messages=append(self.messages,'Vote',rnd,phase,key,variant=int(epoch),epoch=epoch)
                self.messages=append(self.messages,'Timeout',rnd,key='key-0',value=None,epoch=epoch)
        other=dict(CONTEXT,previous='2'*64)
        self.messages=append(self.messages,'Proposal',2,context=other)
        self.messages=append(self.messages,'Vote',0,'Prepare',context=other)

    def test_all_queries_equal_original_scan_with_order_variants_and_wildcards(self):
        old,new=probe(self.messages),probe(self.messages,True)
        for rnd in range(32):
            for kind in index.KINDS:
                for phase in (None,'Prepare','Commit','absent'):
                    for value in (None,VALUE,'3'*64):
                        self.assertEqual(new.signed(CONTEXT,rnd,kind,phase,value),old.signed(CONTEXT,rnd,kind,phase,value))
        self.assertIsNotNone(new._signed_query_index.groups)

    def test_context_scope_and_limit_changes_invalidate(self):
        first,_=query(None,self.messages)
        for context in (dict(CONTEXT,parent_block='9'*64),dict(CONTEXT,parent_height=9)):
            changed,rows=query(first,self.messages,context=context)
            self.assertIsNot(changed,first)
            self.assertEqual(rows,probe(self.messages).signed(context,0,'Vote'))
        changed,_=query(first,self.messages,scope=dict(SCOPE,format='other'))
        self.assertIsNot(changed,first)
        with patch.object(index,'MAX_QUERY_BYTES',index.MAX_QUERY_BYTES-1):
            changed,_=query(first,self.messages);self.assertIsNot(changed,first)

    def test_append_local_flag_unpack_and_complete_proof_replacement_invalidate(self):
        first,_=query(None,self.messages);before=wire.canonical(self.messages.packed())
        more=append(self.messages,'Vote',0,'Prepare','late',variant=99,local=True)
        changed,rows=query(first,more);self.assertIsNot(changed,first)
        self.assertEqual(rows,probe(more).signed(CONTEXT,0,'Vote'))
        marked=more.with_local(next(iter(more)));changed,_=query(changed,marked)
        self.assertIs(changed.messages,marked)
        records,snapshots=self.messages.packed();decoded=Messages.unpack(records,snapshots)
        changed,_=query(first,decoded);self.assertIsNot(changed,first)
        isolated=append(Messages(),'Vote',evidence=[dict(variant='first')])
        cached,_=query(None,isolated);records,snapshots=isolated.packed()
        body=next(iter(records.values()))['body'];replacement=Messages().append(mesh.digest(body),dict(
            format='RLD-REGIONAL-BFT-NETWORK-V2',currency=CONTEXT['currency'],region=CONTEXT['region'],
            body=body,evidence=dict(snapshots=[dict(variant='second')])),VALUE,False)
        changed,rows=query(cached,replacement);self.assertIsNot(changed,cached)
        self.assertEqual(rows,probe(replacement).signed(CONTEXT,0,'Vote'))
        self.assertEqual(wire.canonical(self.messages.packed()),before)

    def test_returned_nested_payload_list_and_input_context_are_isolated(self):
        first,rows=query(None,self.messages,kind='Proposal')
        original=copy.deepcopy(rows);rows[0][0]['snapshot']['extra']['items'].append('changed');rows.clear()
        _,again=query(first,self.messages,kind='Proposal');self.assertEqual(again,original)
        ctx=copy.deepcopy(CONTEXT);first,_=query(None,self.messages,context=ctx);ctx['parent_height']=99
        _,again=query(first,self.messages,kind='Proposal');self.assertEqual(again,original)
        self.assertIsInstance(first.groups,MappingProxyType)
        with self.assertRaises(TypeError):first.groups[('Vote',0)]=()

    def test_budget_refusal_has_no_partial_rows_and_preserves_full_scan(self):
        before=wire.canonical(self.messages.packed())
        with patch.object(index,'MAX_QUERY_BYTES',1):
            refused,rows=query(None,self.messages);self.assertIsNone(rows);self.assertIsNone(refused.groups)
            with patch.object(Messages,'bodies',side_effect=AssertionError('same refused source rebuilt')):
                same,rows=query(refused,self.messages);self.assertIs(same,refused);self.assertIsNone(rows)
            p=probe(self.messages,True)
            self.assertEqual(p.signed(CONTEXT,0,'Vote'),probe(self.messages).signed(CONTEXT,0,'Vote'))
        recovered,rows=query(refused,self.messages);self.assertIsNotNone(recovered.groups)
        self.assertEqual(wire.canonical(self.messages.packed()),before)

    def test_count_refusal_and_unsupported_kind_use_full_scan(self):
        with patch.object(index,'MAX_QUERY_MESSAGES',1):
            witness,rows=query(None,self.messages);self.assertIsNone(rows);self.assertIsNone(witness.groups)
        self.assertEqual(query(None,self.messages,kind='unsupported'),(None,None))
        p=probe(self.messages,True);self.assertEqual(p.signed(CONTEXT,0,'unsupported'),[])

    def test_replaced_byte_maps_with_same_owner_do_not_reuse_witness(self):
        first,_=query(None,self.messages)
        self.messages._records=MappingProxyType(dict(self.messages._records))
        changed,_=query(first,self.messages);self.assertIsNot(changed,first)
        self.messages._snapshots=MappingProxyType(dict(self.messages._snapshots))
        changed2,_=query(changed,self.messages);self.assertIsNot(changed2,changed)

    def test_same_signer_variants_do_not_add_quorum_and_last_order_is_preserved(self):
        messages=Messages()
        for key,variant in (('key-2',0),('key-0',0),('key-1',0),('key-0',1)):
            messages=append(messages,'Vote',0,'Prepare',key,variant=variant,epoch=True)
        old,new=probe(messages),probe(messages,True)
        for p in (old,new):p.with_json=lambda action,payload:(action,payload)
        a=Runtime.quorum(old,CONTEXT,0,'Prepare',VALUE);b=Runtime.quorum(new,CONTEXT,0,'Prepare',VALUE)
        self.assertEqual(a,b);self.assertEqual([v['approval']['key'] for v in b[1]],['key-0','key-1','key-2'])
        self.assertEqual(b[1][0]['approval']['signature'],'1')
        two=append(append(Messages(),'Vote',0,'Prepare','key-0'),'Vote',0,'Prepare','key-0',variant=1,epoch=True)
        self.assertIsNone(Runtime.quorum(probe(two,True),CONTEXT,0,'Prepare',VALUE))

    def test_warm_lookup_decodes_only_selected_rows_and_never_changes_packed_bytes(self):
        p=probe(self.messages,True);before=wire.canonical(pack_state(p.state));p.signed(CONTEXT,0,'Vote','Prepare',VALUE)
        with patch.object(Messages,'bodies',side_effect=AssertionError('warm scan decoded history')):
            actual=p.signed(CONTEXT,0,'Vote','Prepare',VALUE);self.assertEqual(len(actual),6)
        self.assertEqual(wire.canonical(pack_state(p.state)),before)

    def test_failed_save_keeps_original_witness_successful_replacement_clears_it(self):
        p=probe(self.messages,True);p.failed=False;p.state_path=Path('/unused/state.json')
        p.signed(CONTEXT,0,'Vote');witness=p._signed_query_index
        new=dict(p.state,messages=append(self.messages,'Vote',0,'Prepare','late',variant=55))
        with patch.object(mesh,'atomic',side_effect=OSError('diagnostic persistence failure')):
            with self.assertRaises(OSError):Runtime.save(p,new)
        self.assertIs(p.state['messages'],self.messages);self.assertIs(p._signed_query_index,witness)
        p.failed=False
        with patch.object(mesh,'atomic'):Runtime.save(p,new)
        self.assertIsNone(p._signed_query_index);self.assertIs(p.state,new)


if __name__=='__main__':unittest.main()
