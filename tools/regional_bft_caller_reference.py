"""Independent pre-migration Python custody reference; tests only, no native fallback."""
import subprocess
import interstellar_mesh as mesh
import interstellar_transfer as wire
from regional_bft_node import private

def save_head(self, value):
    mesh.require(not self.failed and len(wire.canonical(value))<=8*1024*1024, 'BFT caller-head persistence unavailable/capacity')
    try:
        mesh.atomic(self.head_path,value)
    except BaseException:
        self.failed=True
        raise
    self.head=value

def load_head(self,path,binding,allow_initialization=False):
    value=mesh.load(private(path),8*1024*1024)
    fields={'format','binding','head','pending','outbox'}|({'initialization'} if allow_initialization else set())
    mesh.require(set(value)==fields and value['format']==self.format and value['binding']==binding,
                 'BFT external caller-head binding differs')
    if value['head'] is None:
        mesh.require(allow_initialization and value['pending'] is None and value['outbox'] is None,
                     'only fresh explicit new slot may lack a native head')
    else:mesh.hex32(value['head'])
    return value

def reconcile(self):
    request=self.head['pending']
    try:
        result=self.with_json('bft-sign',request,'--signer-dir',self.signer,'--expected-head',self.head['head'],'--recover-only')
    except (OSError,ValueError,subprocess.TimeoutExpired):
        # Read-only equality proves that this pending request did not advance
        # the retained native history. Never adopt a different native head.
        self.signer_status()
        self.save_head(dict(self.head,pending=None))
        return
    self.save_head(dict(self.head,head=result['head'],pending=None,outbox=result['message']))
