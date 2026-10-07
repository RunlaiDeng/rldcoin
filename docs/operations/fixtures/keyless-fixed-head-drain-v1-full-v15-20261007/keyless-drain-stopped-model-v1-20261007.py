from pathlib import Path
import json,time,tempfile,unittest
from types import SimpleNamespace
from regional_paged_fault_driver import Driver,NativeReadBusy
from regional_paged_fault_launch import SLOTS,PHASES,Config,encoded
from regional_paged_fault_scope import REGIONS
class StoppedDrainTests(unittest.TestCase):
 def model(self,p):
  d=Driver.__new__(Driver);d.currency='1'*64;d.regions={label:str(i+2)*64 for i,label in enumerate(REGIONS)};d.deadline=time.monotonic()+600;d.phase=PHASES[-1];d.processes={};d.terminal=[dict(region=l,index=n,exit_code=0) for l,n in SLOTS];d.configs={};d.queries=[];d.closed=False;d.heights={slot:17 if slot[0]=='earth' else 15 for slot in SLOTS};d.native_heights=dict(d.heights);d.pending=False;d.group=False;d.foreign=False
  for label,n in SLOTS:
   caller=p/f'{label}-{n}.json';caller.write_text(json.dumps(dict(pending=None,outbox=None,head='3'*64,binding='4'*64)));d.configs[PHASES[-1],label,n]=Config(PHASES[-1],label,n,True,encoded({}),encoded(dict(head_file=str(caller),signer_dir=str(p/f'never-opened-{label}-{n}'))),('never-executed',))
  def call(label,n,command,*args):
   d.queries.append((label,n,command))
   if not d.closed and (label,n,command)==('earth',1,'bft-status'):raise NativeReadBusy('model exact live lock refusal')
   if command=='status':return dict(currency='9'*64 if d.foreign else d.currency,region=d.regions[label],height=d.native_heights[label,n])
   if command=='bft-context':return {'context':dict(parent_height=d.native_heights[label,n],currency=d.currency,region=d.regions[label],round=1)}
   if command=='bft-status':return dict(head='3'*64,binding='4'*64)
   if command=='bft-retained-messages':
    context=dict(parent_height=d.native_heights[label,n],currency=d.currency,region=d.regions[label],round=1)
    return [dict(Vote=dict(phase='Commit',context=context,round=1,value='5'*64,approval={'key':str(i)})) for i in range(3)] if d.group else []
   raise AssertionError(command)
  d.call=call;return d
 def test_actual_live_drain_restarts_prefix_under_later_read_lock(self):
  with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='drain-model-') as t:
   d=self.model(Path(t));success=False
   for _ in range(5):
    try:success=bool(d.drain_ready(d.heights))
    except NativeReadBusy:pass
   self.assertFalse(success);self.assertEqual(sum(q==('earth',0,'bft-retained-messages') for q in d.queries),5);self.assertFalse(any(q[0]!='earth' for q in d.queries))
 def test_same_original_drain_predicate_after_clean_stop_checks_all12(self):
  with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='drain-model-') as t:
   d=self.model(Path(t));d.closed=True;self.assertTrue(d.stopped_drain());self.assertEqual({(l,n) for l,n,c in d.queries if c=='bft-retained-messages'},set(SLOTS));self.assertEqual(sum(c=='status' for l,n,c in d.queries),12)
 def test_live_process_unclean_stop_or_wrong_phase_refuse_before_read(self):
  for why in ('live','unclean','phase','incomplete'):
   with self.subTest(why=why),tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='drain-model-') as t:
    d=self.model(Path(t));d.closed=True
    if why=='live':d.processes[('earth',0)]=SimpleNamespace()
    if why=='unclean':d.terminal[-1]['exit_code']=-15
    if why=='phase':d.phase=PHASES[0]
    if why=='incomplete':d.terminal=d.terminal[:-1]
    with self.assertRaises(ValueError):d.stopped_drain()
    self.assertFalse(d.queries)
 def test_unknown_telemetry_and_unequal_replica_observations_cannot_trigger_stop(self):
  with tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='drain-model-') as t:
   d=self.model(Path(t));self.assertTrue(d.keyless_observations_ready(d.heights));h=dict(d.heights);h['earth',0]=None;self.assertFalse(d.keyless_observations_ready(h));h['earth',0]=18;self.assertFalse(d.keyless_observations_ready(h));h['earth',0]=True;self.assertFalse(d.keyless_observations_ready(h))
 def test_native_domain_cap_and_divergence_do_not_receive_drain_credit(self):
  for why in ('foreign','region','cap','different'):
   with self.subTest(why=why),tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='drain-model-') as t:
    d=self.model(Path(t));d.closed=True
    if why=='foreign':d.foreign=True
    elif why=='cap':d.native_heights['earth',0]=28
    elif why=='different':d.native_heights['earth',0]=18
    else:
     old=d.call
     def wrong(*args):
      v=old(*args)
      if args[2]=='status':v['region']='9'*64
      return v
     d.call=wrong
    if why=='different':self.assertFalse(d.stopped_drain())
    else:
     with self.assertRaises(ValueError):d.stopped_drain()
 def test_pending_caller_head_and_complete_commit_group_remain_refusals(self):
  for why in ('pending','outbox','head','group'):
   with self.subTest(why=why),tempfile.TemporaryDirectory(dir='/Users/galaxy/GitHub/rldcoin/tmp',prefix='drain-model-') as t:
    d=self.model(Path(t));d.closed=True;c=json.loads(d.configs[PHASES[-1],'earth',0].bft);p=Path(c['head_file']);v=json.loads(p.read_text())
    if why in ('pending','outbox'):v[why]={};p.write_text(json.dumps(v));self.assertFalse(d.stopped_drain())
    elif why=='head':v['head']='5'*64;p.write_text(json.dumps(v));
    if why=='head':
     with self.assertRaises(ValueError):d.stopped_drain()
    if why=='group':d.group=True;self.assertFalse(d.stopped_drain())
