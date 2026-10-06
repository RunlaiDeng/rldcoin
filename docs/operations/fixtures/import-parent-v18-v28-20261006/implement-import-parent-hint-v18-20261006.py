from pathlib import Path
r=Path.cwd();p=r/'tools/regional_bft_node.py';s=p.read_text();s=s.replace('Scheduling only for a Native-checked round-zero empty two-block proposal.','Scheduling only for a Native-checked empty candidate and bounded parent.').replace('    Complex commands, epochs, timeout rounds and other shapes use ordinary','    Only parent Import commands (original maximum 16) have a typed encoding.\n    Other commands, epochs, timeout rounds and other shapes use ordinary')
a=s.index("    for block in snapshot['blocks']:");z=s.index('    encode=lambda value:',a)
s=s[:a]+'''    for index,block in enumerate(snapshot['blocks']):
        if (type(block) is not dict or set(block)!={'header','commands'}
                or type(block['commands']) is not list or len(block['commands'])>16
                or index==1 and block['commands']!=[]
                or type(block['header']) is not dict or set(block['header'])!=set(header_fields)):return False
        commands=[]
        for command in block['commands']:
            if (type(command) is not dict or set(command)!={'Import'}
                    or type(command['Import']) is not dict or set(command['Import'])!={'snapshot','export'}):return False
            imp=command['Import'];mesh.hex32(imp['snapshot']);mesh.hex32(imp['export'])
            commands.append({'Import':{'snapshot':imp['snapshot'],'export':imp['export']}})
        h={k:block['header'][k] for k in header_fields};headers.append(h);blocks.append(dict(header=h,commands=commands))
'''+s[z:];s=s.replace("    parent,child=headers;statement=snapshot['statement']", "    parent,child=headers;statement=snapshot['statement']\n    if (blocks[0]['commands'] and parent['commands']!=hashlib.sha256(\n            b'RLD-REGIONAL-FIXTURE-V1:commands\\0'+encode(blocks[0]['commands'])).hexdigest()):return False");compile(s,str(p),'exec');p.write_text(s)
p=r/'tools/interstellar_mesh.py';s=p.read_text().replace('RLD-CONTACT-TRANSIT-SCHEDULER-V17','RLD-CONTACT-TRANSIT-SCHEDULER-V18');p.write_text(s)
# Add only the relevant delivery and bounds assertions; all old methods exact.
import ast
p=r/'tools/test_interstellar_mesh.py';s=p.read_text();t=ast.parse(s);cl=next(x for x in t.body if isinstance(x,ast.ClassDef) and x.name=='MeshTests');f=next(x for x in cl.body if isinstance(x,ast.FunctionDef) and x.name=='test_prepared_empty_proposal_priority_reaches_destination_after_full_retry');lines=s.splitlines(True);new=''.join(lines[f.lineno-1:f.end_lineno]);new=new.replace('test_prepared_empty_proposal_priority_reaches_destination_after_full_retry','test_prepared_import_parent_proposal_priority_reaches_destination_after_full_retry').replace('signed_ground_empty_proposal(context,key)','signed_ground_import_parent_proposal(context,key)');anchor="                changed=copy.deepcopy(envelope);changed['evidence']['snapshots']";a=new.index(anchor)
new=new[:a]+'''                for mutation in ('over16','unknown','extra','hex','header_hash'):
                    changed=copy.deepcopy(envelope);snap=changed['body']['Signed']['Proposal']['snapshot'];parent=snap['blocks'][0]
                    if mutation=='over16':parent['commands']*=17
                    elif mutation=='unknown':parent['commands']=[{'Spend':{}}]
                    elif mutation=='extra':parent['commands'][0]['Import']['extra']=None
                    elif mutation=='hex':parent['commands'][0]['Import']['export']='z'*64
                    else:parent['header']['commands']='8'*64
                    invalid=Messages().append(mesh.digest(changed['body']),changed,None,True)
                    self.assertEqual(bft.commit_carriage_frames(invalid,context,keys,NETWORK,context['region']),())
'''+new[a:];at=sum(map(len,lines[:f.end_lineno]));s=s[:at]+'\n\n'+new+s[at:];compile(s,str(p),'exec');p.write_text(s)
