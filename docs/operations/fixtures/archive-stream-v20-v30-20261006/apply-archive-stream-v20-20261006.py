from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin')
p=r/'tools/interstellar_frame_digest.py';s=p.read_text();old='def commitment(transit):\n    """Return exact (canonical SHA-256, size); never validate a signature."""\n    value = transit\n    for key in PATH:';new='''def commitment(transit):
    """Return exact (canonical SHA-256, size); never validate a signature."""
    return _commitment(transit, PATH)


def archive_commitment(blob):
    """Exact complete archive bytes, with no retained witness or authority.

    Receipt-only or unsupported shapes retain the ordinary canonical path.
    Archive read still authenticates actual files, full transit and receipt.
    """
    return _commitment(blob, ('transit',) + PATH)


def _commitment(transit, path):
    value = transit
    for key in path:''';assert s.count(old)==1;s=s.replace(old,new);assert s.count('_split(transit, PATH)')==1;s=s.replace('_split(transit, PATH)','_split(transit, path)');compile(s,str(p),'exec');p.write_text(s)
p=r/'tools/interstellar_mesh.py';s=p.read_text();assert s.count("RLD-CONTACT-TRANSIT-SCHEDULER-V19")==1;s=s.replace('RLD-CONTACT-TRANSIT-SCHEDULER-V19','RLD-CONTACT-TRANSIT-SCHEDULER-V20');assert s.count('payload==evidence.canonical(frame)')==1;s=s.replace('payload==evidence.canonical(frame)','payload==frame_digest.packet_body_bytes(frame)');old="expanded_size=len(evidence.canonical(preview))+len(evidence.canonical(frame['frame']))+8+bool(transit['packet']['body'])";assert s.count(old)==1;new="""# The complete frame object was compared to its exact canonical
            # bytes above. Reuse that byte length, including all JSON escapes,
            # by subtracting the same object's empty-string image. No frame
            # encoding or authentication result survives this operation.
            frame_size=len(payload)-len(evidence.canonical(dict(frame,frame='')))+2
            expanded_size=len(evidence.canonical(preview))+frame_size+8+bool(transit['packet']['body'])""";s=s.replace(old,new)
old="""        expanded=evidence.canonical(blob)
        require(len(expanded)==body['expanded_size_bytes'] and len(expanded)<=MAX_STATE
                and hashlib.sha256(expanded).hexdigest()==body['expanded_sha256'],""";new="""        expanded_hash,expanded_size=frame_digest.archive_commitment(blob)
        require(expanded_size==body['expanded_size_bytes'] and expanded_size<=MAX_STATE
                and expanded_hash==body['expanded_sha256'],""";assert s.count(old)==1;s=s.replace(old,new);compile(s,str(p),'exec');p.write_text(s)
