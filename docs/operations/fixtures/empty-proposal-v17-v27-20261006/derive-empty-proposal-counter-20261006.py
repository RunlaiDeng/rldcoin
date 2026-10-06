from pathlib import Path
import ast
r=Path.cwd();p=r/'tools/test_interstellar_mesh.py';s=p.read_text();utility='''def signed_ground_empty_proposal(context, key):
    """Real Native-domain signature; no Native proof, work or ledger authority."""
    public=key.public_key().public_bytes(mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex()
    parent=dict(currency=context['currency'],region=context['region'],parent='2'*64,
        anchor=context['previous'],height=context['parent_height'],miner=public,
        commands='4'*64,state=context['parent_state'],nonce=0)
    block_hash=lambda h:evidence.hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\\0'+
        json.dumps(h,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
    context=dict(context,parent_block=block_hash(parent))
    child=dict(parent,parent=context['parent_block'],height=context['parent_height']+1,state='5'*64)
    statement=dict(currency=context['currency'],region=context['region'],height=child['height'],
        block=block_hash(child),state=child['state'],previous=context['previous'],epoch=context['epoch'])
    snapshot=dict(base=context['previous'],statement=statement,approvals=[],
        blocks=[dict(header=parent,commands=[]),dict(header=child,commands=[])],epochs=[])
    signed=b'RLD-REGIONAL-FIXTURE-V1:bft-proposal-v1\\0'+json.dumps(
        [0,snapshot,None,public],separators=(',',':'),ensure_ascii=False).encode()
    signature=key.sign(signed).hex();key.public_key().verify(bytes.fromhex(signature),signed)
    return context,dict(round=0,snapshot=snapshot,timeout=None,leader=dict(key=public,signature=signature))


'''
assert 'def signed_ground_empty_proposal' not in s;s=s.replace('class Fixture:',utility+'class Fixture:',1);t=ast.parse(s);cl=next(x for x in t.body if isinstance(x,ast.ClassDef) and x.name=='MeshTests');f=next(x for x in cl.body if isinstance(x,ast.FunctionDef) and x.name=='test_prepared_prepare_keeps_spare_after_native_current_commit_hint');lines=s.splitlines(True);new=''.join(lines[f.lineno-1:f.end_lineno]);new=new.replace('test_prepared_prepare_keeps_spare_after_native_current_commit_hint','test_prepared_empty_proposal_keeps_spare_after_native_current_vote_hint').replace('bytes([4])','bytes([5])').replace('prepared Prepare','prepared Proposal').replace('Prepare spare','Proposal spare');a=new.index('        signed = ');z=new.index('        messages = ',a);new=new[:a]+'''        context,proposal=signed_ground_empty_proposal(context,key)
        envelope=dict(format=bft.NETWORK,currency=NETWORK,region=context['region'],
            evidence=dict(snapshots=[]),body=dict(Signed=dict(Proposal=proposal)))
'''+new[z:]
a=new.index('                for field,value in ((\'phase\'');z=new.index('                changed=copy.deepcopy(envelope);changed[\'evidence\']',a)
new=new[:a]+'''                for field,value in (('signature','0'*128),('key','f'*64)):
                    changed=copy.deepcopy(envelope);changed['body']['Signed']['Proposal']['leader'][field]=value
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
'''+new[z:];at=sum(map(len,lines[:f.end_lineno]));s=s[:at]+'\n\n'+new+s[at:];compile(s,str(p),'exec');p.write_text(s)
b=r/'tmp/default-relay-20260930';old=b/'check-current-prepare-ground-20261006.py';new=b/'check-current-empty-proposal-ground-20261006.py';assert not new.exists();q=old.read_text().replace("'prepare-delivery-v16')","'prepare-delivery-v16','proposal-baseline-v16','proposal-related-v17','proposal-delivery-v17')");compile(q,str(new),'exec');new.write_text(q)
