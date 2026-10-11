"""Adapter refusal models only; synthetic Native replies grant no authority."""
import copy
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import interstellar_transfer as wire
import regional_bft_candidate as selection


class CandidateBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.calls=[];self.change=None
        self.context={'synthetic_context_only':True}
        self.command={'Import':{'snapshot':'1'*64,'export':'2'*64}}
        self.runtime=SimpleNamespace(root=Path(self.temp.name),miner='3'*64,with_json=self.call)

    def call(self,action,value,*args):
        self.calls.append((action,copy.deepcopy(value)))
        if action=='bft-candidate':
            self.assertEqual(args[:3],('--miner',self.runtime.miner,'--context'))
            self.assertEqual(wire.decode_json(Path(args[3]).read_bytes()),self.context)
            return {'synthetic_unsigned_candidate':True}
        self.assertEqual(action,'bft-candidate-select')
        ident=mesh.digest(value['commands'][0])
        result=dict(format=selection.FORMAT,context=value['context'],
            request_sha256=hashlib.sha256(wire.canonical(value)).hexdigest(),seen=[ident],
            attempts=[dict(index=0,command_id=ident,selected=True)],selected_count=1,
            ledger_changed=False,signing_authority=False)
        return self.change(result) if self.change else result

    def test_exact_reply_transports_only_native_selected_indices_and_fresh_context(self):
        self.assertEqual(selection.select(self.runtime,self.context,[self.command]),{'synthetic_unsigned_candidate':True})
        self.assertEqual([c[0] for c in self.calls],['bft-candidate-select','bft-candidate'])
        self.assertEqual(self.calls[1][1],[self.command]);self.assertEqual(list(self.runtime.root.iterdir()),[])

    def test_unknown_binary_busy_and_invalid_native_reply_never_fallback_or_finalize(self):
        for reason in ('unknown command','native locked','invalid current native history'):
            self.calls=[]
            def refuse(result):raise ValueError(reason)
            self.change=refuse
            with self.assertRaises(ValueError):selection.select(self.runtime,self.context,[self.command])
            self.assertEqual([c[0] for c in self.calls],['bft-candidate-select'])
        changes=[{'format':'old'},{'context':{}},{'request_sha256':'0'*64},{'ledger_changed':True},
                 {'signing_authority':True},{'selected_count':True},{'selected_count':5},
                 {'attempts':[]},{'seen':[]},{'unexpected':True}]
        for fields in changes:
            self.calls=[];self.change=lambda result:{**result,**fields}
            with self.subTest(fields=fields),self.assertRaises(ValueError):selection.select(self.runtime,self.context,[self.command])
            self.assertEqual([c[0] for c in self.calls],['bft-candidate-select'])

    def test_altered_duplicate_out_of_order_or_nonboolean_attempts_never_map_commands(self):
        changes=[{'index':True},{'index':-1},{'index':1},{'selected':1},{'command_id':'0'*64}]
        for fields in changes:
            self.calls=[];self.change=lambda r:{**r,'attempts':[{**r['attempts'][0],**fields}]}
            with self.subTest(fields=fields),self.assertRaises(ValueError):selection.select(self.runtime,self.context,[self.command])
            self.assertEqual(len(self.calls),1)
        self.calls=[];self.change=lambda r:{**r,'attempts':r['attempts']*2}
        with self.assertRaises(ValueError):selection.select(self.runtime,self.context,[self.command])
        self.assertEqual(len(self.calls),1)

    def test_single_request_capacity_refuses_before_call_or_disposable_file(self):
        with patch.object(selection,'MAX_BYTES',10),self.assertRaises(ValueError):selection.select(self.runtime,self.context,[self.command])
        self.assertEqual(self.calls,[]);self.assertEqual(list(self.runtime.root.iterdir()),[])


if __name__=='__main__':unittest.main()
