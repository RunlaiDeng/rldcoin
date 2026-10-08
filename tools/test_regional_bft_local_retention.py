"""Exact local construction paths; synthetic responses grant no Native authority."""
import ast
import copy
from collections import Counter
from pathlib import Path
import unittest
import regional_bft_node as bft
import test_regional_bft_local_envelope as outbox_tests


class LocalRetentionTests(unittest.TestCase):
    def boundary(self):
        check=outbox_tests.LocalEnvelopeTests()
        return check,check.runtime()

    def test_actual_startup_and_finalization_calls_use_one_verified_read(self):
        tree=ast.parse(Path(bft.__file__).read_text())
        selected=[]
        for method in (n for n in ast.walk(tree) if isinstance(n,ast.FunctionDef) and n.name in ('__init__','_tick')):
            for statement in ast.walk(method):
                if not isinstance(statement,ast.Expr) or not isinstance(statement.value,ast.Call):continue
                call=statement.value
                if not isinstance(call.func,ast.Attribute) or not isinstance(call.func.value,ast.Name) or call.func.value.id!='self' or call.func.attr not in ('retain','retain_local_body'):continue
                literals=[n for n in ast.walk(call) if isinstance(n,ast.Dict) and any(isinstance(k,ast.Constant) and k.value in ('Signed','Finalized') for k in n.keys)]
                if not literals:continue
                kinds={k.value for literal in literals for k in literal.keys
                       if isinstance(k,ast.Constant) and k.value in ('Signed','Finalized')}
                self.assertEqual(len(kinds),1)
                selected.append((method.name,next(iter(kinds)),statement))
        # Both ordinary delayed-certificate and newly completed own-Commit
        # finalization must use the same complete Native local-envelope path.
        self.assertEqual(Counter((method,kind) for method,kind,_ in selected),
                         Counter({('__init__','Signed'):1,('__init__','Finalized'):1,
                                  ('_tick','Finalized'):2}))
        for method,kind,statement in selected:
            with self.subTest(method=method,source=ast.unparse(statement)):
                check,runtime=self.boundary();before=copy.deepcopy(runtime.head)
                exec(compile(ast.Module(body=[statement],type_ignores=[]),'<exact-local-retention-call>','exec'),dict(self=runtime,message={'Vote':{'synthetic':True}},local=[{'synthetic_certificate':True}],certificate={'synthetic_certificate':True}))
                self.assertEqual(check.actions,['bft-network-local-envelope'])
                self.assertEqual(len(check.retained),1)
                self.assertEqual(check.retained[0][2:],(False,True))
                self.assertEqual(runtime.head,before)

    def test_signed_and_finalized_native_or_durable_failure_keeps_caller_state(self):
        for body in ({'Signed':{'Vote':{'synthetic':True}}},{'Finalized':{'synthetic_certificate':True}}):
            for failure in ('native','retention'):
                with self.subTest(body=body,failure=failure):
                    _,runtime=self.boundary();before=copy.deepcopy(runtime.head)
                    if failure=='native':runtime.with_json=lambda *a:(_ for _ in ()).throw(ValueError('Native refused complete proof'))
                    else:runtime._retain_checked=lambda *a,**k:(_ for _ in ()).throw(OSError('durable retention failed'))
                    with self.assertRaises((ValueError,OSError)):runtime.retain_local_body(body)
                    self.assertEqual(runtime.head,before)

    def test_other_profiles_keep_original_full_path(self):
        for body in ({'Signed':{'Vote':{'synthetic':True}}},{'Finalized':{'synthetic_certificate':True}}):
            check,runtime=self.boundary();runtime.format='other-profile'
            runtime.retain_local_body(body)
            self.assertEqual(check.actions,['proof','bft-network-pack','bft-network-check'])
            self.assertEqual(check.retained[0][2:],(False,True))


if __name__=='__main__':unittest.main()
