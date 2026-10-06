from pathlib import Path
import ast
r=Path.cwd();p=r/'tools/test_interstellar_mesh.py';s=p.read_text();utility='''def signed_ground_import_parent_proposal(context, key):
    """Fresh ground Import-parent bytes and real proposal signature; no authority."""
    context,proposal=signed_ground_empty_proposal(context,key)
    snapshot=proposal['snapshot'];parent,child=snapshot['blocks']
    parent['commands']=[{'Import':{'snapshot':'6'*64,'export':'7'*64}}]
    encode=lambda v:json.dumps(v,separators=(',',':'),ensure_ascii=False).encode()
    parent['header']['commands']=evidence.hashlib.sha256(
        b'RLD-REGIONAL-FIXTURE-V1:commands\\0'+encode(parent['commands'])).hexdigest()
    block_hash=lambda h:evidence.hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\\0'+encode(h)).hexdigest()
    context=dict(context,parent_block=block_hash(parent['header']));child['header']['parent']=context['parent_block']
    snapshot['statement']['block']=block_hash(child['header'])
    data=b'RLD-REGIONAL-FIXTURE-V1:bft-proposal-v1\\0'+encode([0,snapshot,None,proposal['leader']['key']])
    proposal['leader']['signature']=key.sign(data).hex();key.public_key().verify(bytes.fromhex(proposal['leader']['signature']),data)
    return context,proposal


'''
assert 'def signed_ground_import_parent_proposal' not in s;s=s.replace('class Fixture:',utility+'class Fixture:',1);t=ast.parse(s);cl=next(x for x in t.body if isinstance(x,ast.ClassDef) and x.name=='MeshTests');f=next(x for x in cl.body if isinstance(x,ast.FunctionDef) and x.name=='test_prepared_empty_proposal_keeps_spare_after_native_current_vote_hint');lines=s.splitlines(True);new=''.join(lines[f.lineno-1:f.end_lineno]);new=new.replace('test_prepared_empty_proposal_keeps_spare_after_native_current_vote_hint','test_prepared_import_parent_proposal_keeps_spare_after_native_current_hint').replace('signed_ground_empty_proposal(context,key)','signed_ground_import_parent_proposal(context,key)');at=sum(map(len,lines[:f.end_lineno]));s=s[:at]+'\n\n'+new+s[at:];compile(s,str(p),'exec');p.write_text(s)
b=r/'tmp/default-relay-20260930';old=b/'check-current-empty-proposal-ground-20261006.py';new=b/'check-current-import-parent-ground-20261006.py';assert not new.exists();q=old.read_text().replace("'proposal-delivery-v17')","'proposal-delivery-v17','import-parent-baseline-v17','import-parent-related-v18','import-parent-delivery-v18')");compile(q,str(new),'exec');new.write_text(q)
