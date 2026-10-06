def current_finalized_hint(snapshot, context, keys):
    """Extra carriage filter for an exact Native-checked current checkpoint.

    The original retained-envelope authentication is still required. These
    complete quorum signatures narrow scheduling only, never validate blocks,
    state, evidence, epochs, custody or a receiver's Native acceptance.
    """
    fields=('currency','region','height','block','state','previous','epoch')
    context_fields=('currency','region','epoch','previous','parent_height','parent_block','parent_state')
    if (type(snapshot) is not dict or set(snapshot)!={'base','bft','statement','approvals','blocks','epochs'}
            or snapshot['approvals']!=[] or snapshot['epochs']!=[]
            or type(snapshot['blocks']) is not list or len(snapshot['blocks'])>256):return False
    statement=snapshot['statement'];certificate=snapshot['bft']
    if (type(statement) is not dict or set(statement)!=set(fields)
            or type(statement['height']) is not int or statement['height']<1
            or statement['height']!=context['parent_height']
            or (statement['currency'],statement['region'],statement['epoch'],statement['block'],statement['state'])
               !=(context['currency'],context['region'],context['epoch'],context['parent_block'],context['parent_state'])
            or snapshot['base']!=statement['previous']
            or type(certificate) is not dict or set(certificate)!={'prepared','committed'}):return False
    encode=lambda value:wire.json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
    value=hashlib.sha256(b'RLD-REGIONAL-FIXTURE-V1:unanimous-checkpoint\0'+
                        encode({k:statement[k] for k in fields})).hexdigest()
    if value!=context['previous']:return False
    previous=None;round_number=None
    for name,phase in (('prepared','Prepare'),('committed','Commit')):
        quorum=certificate[name]
        if (type(quorum) is not dict or set(quorum)!={'context','round','value','phase','votes'}
                or type(quorum['round']) is not int or not 0<=quorum['round']<32
                or quorum['value']!=value or quorum['phase']!=phase
                or type(quorum['votes']) is not list or not 3<=len(quorum['votes'])<=4):return False
        parent=quorum['context']
        if (type(parent) is not dict or set(parent)!=set(context_fields)
                or type(parent['parent_height']) is not int or parent['parent_height']+1!=statement['height']
                or (parent['currency'],parent['region'],parent['epoch'],parent['previous'])
                   !=(statement['currency'],statement['region'],statement['epoch'],statement['previous'])):return False
        mesh.hex32(parent['parent_block']);mesh.hex32(parent['parent_state'])
        if name=='prepared':previous=parent;round_number=quorum['round']
        elif parent!=previous or quorum['round']!=round_number:return False
        last=None
        for vote in quorum['votes']:
            if (type(vote) is not dict or set(vote)!={'context','round','value','phase','approval'}
                    or vote['context']!=parent or type(vote['round']) is not int
                    or vote['round']!=quorum['round'] or vote['value']!=value or vote['phase']!=phase
                    or type(vote['approval']) is not dict or set(vote['approval'])!={'key','signature'}):return False
            approval=vote['approval'];key=approval['key']
            if key not in keys or last is not None and key<=last:return False
            data=b'RLD-REGIONAL-FIXTURE-V1:bft-vote-v1\0'+encode(
                [{k:parent[k] for k in context_fields},quorum['round'],value,phase,key])
            mesh.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
                bytes.fromhex(approval['signature']),data)
            last=key
    return True


