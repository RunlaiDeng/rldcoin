#!/usr/bin/env python3
"""Check actual binary self-report against independently enumerated source."""
import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from verify import capture, unique

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--binary',type=Path,required=True)
p.add_argument('--root',type=Path,default=Path('.'))
p.add_argument('--report',type=Path,required=True)
a=p.parse_args()
raw=subprocess.check_output([str(a.binary.resolve()),'implementation-source'],timeout=30)
assert len(raw)<=4*1024*1024
embedded=json.loads(raw,object_pairs_hook=unique)
actual=capture(a.root)
assert embedded==actual, 'binary source inventory mismatch'
with tempfile.TemporaryDirectory(prefix='rld-source-check-') as tmp:
    manifest=Path(tmp)/'manifest.json';manifest.write_bytes(raw)
    base=['python3','-B',str(Path(__file__).with_name('verify.py')),'--root',str(a.root),'--manifest',str(manifest),'--expected-commitment']
    subprocess.run(base+[actual['commitment']],check=True,capture_output=True,timeout=60)
    wrong=subprocess.run(base+['0'*64],capture_output=True,timeout=60)
    assert wrong.returncode!=0
    embedded['files'][0]['sha256']='0'*64
    manifest.write_text(json.dumps(embedded))
    tampered=subprocess.run(base+[actual['commitment']],capture_output=True,timeout=60)
    assert tampered.returncode!=0
report={k:v for k,v in actual.items() if k!='files'}
report.update(result='PASS',checks=['actual Rust inventory equals independent Python source capture','separately expected commitment mismatch rejected','tampered inventory rejected'],binary_attested=False,upgrade_authorized=False)
a.report.parent.mkdir(parents=True,exist_ok=True)
a.report.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
