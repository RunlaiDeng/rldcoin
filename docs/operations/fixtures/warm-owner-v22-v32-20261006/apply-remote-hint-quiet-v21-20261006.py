from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');p=r/'tools/regional_bft_node.py';s=p.read_text();old='and len(rows)<=MAX_MESSAGES and len(recipients)<=mesh.MAX_CONTACTS):';new='and len(rows)<=MAX_MESSAGES and len(self.state[\'messages\'])<=MAX_MESSAGES\n                and len(recipients)<=mesh.MAX_CONTACTS):';assert s.count(old)==1;s=s.replace(old,new);old="'local_complete_envelope_ids':rows,'recipients':recipients})";new="""'local_complete_envelope_ids':rows,
                # Remote Native-checked envelopes also supply current-frame
                # scheduling hints. A new complete retained frame must invalidate
                # this quiet inventory even when all local recipient pairs match.
                # Exact IDs only; no proof, context or signing authority cached.
                'retained_complete_envelope_ids':[(self.state['messages'].content(i),i)
                                                 for i in sorted(self.state['messages'])],
                'recipients':recipients})""";assert s.count(old)==1;s=s.replace(old,new);compile(s,str(p),'exec');p.write_text(s)
p=r/'tools/interstellar_mesh.py';s=p.read_text();assert s.count('RLD-CONTACT-TRANSIT-SCHEDULER-V20')==1;p.write_text(s.replace('RLD-CONTACT-TRANSIT-SCHEDULER-V20','RLD-CONTACT-TRANSIT-SCHEDULER-V21'))
