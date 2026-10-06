from pathlib import Path
import hashlib,json,sys
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');sys.path.insert(0,str(r/'tools'))
from regional_paged_fault_scope import inventory
assert len(sys.argv)==4
root,seal,expected=sys.argv[1:];root=Path(root);seal=Path(seal)
assert hashlib.sha256(seal.read_bytes()).hexdigest()==expected
rows=json.loads(seal.read_text());assert str(root) in rows and inventory(root)==rows[str(root)]
print(json.dumps(dict(completed=True,files=len(rows[str(root)]))),flush=True)
