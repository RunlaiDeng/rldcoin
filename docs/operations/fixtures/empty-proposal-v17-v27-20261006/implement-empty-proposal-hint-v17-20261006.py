from pathlib import Path
r=Path.cwd();p=r/'tools/regional_bft_node.py';s=p.read_text();helper='''def current_empty_proposal_hint(proposal, context, keys):
    """Scheduling only for a Native-checked round-zero empty two-block proposal.

    Complex commands, epochs, timeout rounds and other shapes use ordinary
    carriage. This extra exact signature check supplies no Native acceptance.
    """
    if (type(proposal) is not dict or set(proposal)!={'round','snapshot','timeout','leader'}
            or type(proposal['round']) is not int or proposal['round']!=0
            or proposal['timeout'] is not None):return False
    snapshot=proposal['snapshot'];leader=proposal['leader']
    if (type(snapshot) is not dict or set(snapshot)!={'base','statement','approvals','blocks','epochs'}
            or snapshot['base'] is None or snapshot['base']!=context['previous']
            or snapshot['approvals']!=[] or snapshot['epochs']!=[]
            or type(snapshot['blocks']) is not list or len(snapshot['blocks'])!=2
            or type(leader) is not dict or set(leader)!={'key','signature'}
            or leader['key']!=keys[context['parent_height']%4]):return False
    header_fields=('currency','region','parent','anchor','height','miner','commands','state','nonce')
    statement_fields=('currency','region','height','block','state','previous','epoch')
    headers=[];blocks=[]
    for block in snapshot['blocks']:
        if (type(block) is not dict or set(block)!={'header','commands'} or block['commands']!=[]
                or type(block['header']) is not dict or set(block['header'])!=set(header_fields)):return False
        h={k:block['header'][k] for k in header_fields};headers.append(h);blocks.append(dict(header=h,commands=[]))
    encode=lambda value:wire.json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    block_hash=lambda h:hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:block\\0'+encode(h)).hexdigest()
    parent,child=headers;statement=snapshot['statement']
    if (type(statement) is not dict or set(statement)!=set(statement_fields)
            or parent['height']!=context['parent_height'] or parent['state']!=context['parent_state']
            or block_hash(parent)!=context['parent_block']
            or child['parent']!=context['parent_block'] or child['anchor']!=context['previous']
            or child['height']!=context['parent_height']+1
            or any(h['currency']!=context['currency'] or h['region']!=context['region'] for h in headers)
            or statement!=dict(currency=context['currency'],region=context['region'],height=child['height'],
                block=block_hash(child),state=child['state'],previous=context['previous'],epoch=context['epoch'])):return False
    ordered=dict(base=snapshot['base'],statement={k:statement[k] for k in statement_fields},
                 approvals=[],blocks=blocks,epochs=[])
    data=b'RLD-REGIONAL-FIXTURE-V1:bft-proposal-v1\\0'+encode([0,ordered,None,leader['key']])
    mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(leader['key'])).verify(
        bytes.fromhex(leader['signature']),data)
    return True


'''
assert 'def current_empty_proposal_hint' not in s;s=s.replace('def commit_carriage_frames(',helper+'def commit_carriage_frames(',1)
a=s.index("        vote=body.get('Signed',{}).get('Vote',{})");z=s.index("            expanded_bytes+=",a)
s=s[:a]+'''        signed=body.get('Signed',{});vote=signed.get('Vote',{});proposal=signed.get('Proposal')
        try:
            if proposal is not None:
                if not current_empty_proposal_hint(proposal,context,keys):continue
            else:
                if vote.get('phase') not in ('Prepare','Commit') or vote.get('context')!=context:continue
                approval=vote['approval'];key=approval['key']
                if key not in keys:continue
                data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\\0'+wire.json.dumps(
                    [{k:context[k] for k in fields},vote['round'],vote['value'],vote['phase'],key],
                    separators=(',',':'),ensure_ascii=False).encode()
                mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                    bytes.fromhex(approval['signature']),data)
'''+s[z:];s=s.replace('Exact current Prepare/Commit frames from Native-checked Messages.','Exact current votes and bounded empty proposals from Native-checked Messages.');compile(s,str(p),'exec');p.write_text(s)
p=r/'tools/interstellar_mesh.py';s=p.read_text().replace('RLD-CONTACT-TRANSIT-SCHEDULER-V16','RLD-CONTACT-TRANSIT-SCHEDULER-V17').replace('current Prepare/Commit whose send/replay failed','current signed frame whose send/replay failed');p.write_text(s)
