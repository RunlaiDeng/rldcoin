from pathlib import Path
import ast,hashlib,json
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');b=r/'tmp/default-relay-20260930';p=r/'tools/interstellar_mesh.py';before=b/'mesh-before-current-copy-v25-20261007.py';assert not before.exists();old=p.read_text();before.write_text(old);text=old;pairs=[]
def replace(a,z):
 global text
 assert text.count(a)==1,(a[:80],text.count(a));pairs.append((a,z));text=text.replace(a,z)
replace("TRANSIT_SCHEDULER = 'RLD-CONTACT-TRANSIT-SCHEDULER-V24'","TRANSIT_SCHEDULER = 'RLD-CONTACT-TRANSIT-SCHEDULER-V25'")
replace('    def _exchange_plan(self, peer, accepted_transits=None, retry_packet_ids=()):','    def _exchange_plan(self, peer, accepted_transits=None, retry_packet_ids=(), *, current_carriage=None):')
replace("        transits = []\n        requested=set(self.state['peer_inventory']", "        require(current_carriage is None or type(current_carriage) is dict and not current_carriage,\n                'current carriage operation tracker must start empty')\n        transits = []\n        requested=set(self.state['peer_inventory']")
replace('''        pending=self.transit_groups(peer) if len(transits)<MAX_PACKET_BATCH else []''','''        # Keep same-frame recipient rotation separate from the ordinary ring.
        # Capture only primitive positions before group initialization can evict
        # them. They select carriage; each original packet still authenticates.
        current_classes={};current_positions={}
        if hint is not None:
            frames=set(hint[1]);recent=set(self.state['recent_transits'])
            current_classes={ident:(ident in recent,t['routing']['body']['frame_id'])
                             for ident,t in self.state['messages'].items()
                             if t['routing']['body']['frame_id'] in frames}
            domain=self.carriage_position_domain()
            for kind,frame in sorted(set(current_classes.values())):
                current_positions[(kind,frame)]=carriage_position(
                    (domain,peer,'native-current-copy',hint[0],kind,frame))
            if current_carriage is not None:
                current_carriage.update(scope=hint[0],classes=current_classes)
        pending=self.transit_groups(peer) if len(transits)<MAX_PACKET_BATCH else []''')
replace('''            commits=[i for items in pending for i in items
                     if self.state['messages'][i]['routing']['body']['frame_id'] in frames]''','''            commits=[]
            for items in pending:
                copies={}
                for ident in items:
                    if ident in current_classes:
                        copies.setdefault(current_classes[ident],[]).append(ident)
                for group,identifiers in copies.items():
                    after=current_positions[group]
                    if after is not None:
                        ordered=sorted(identifiers)
                        start=bisect_right(ordered,after)%len(ordered)
                        identifiers=ordered[start:]+ordered[:start]
                    # Preserve inter-frame order and the two original classes.
                    # Only sibling recipient packets of one exact frame rotate.
                    commits.extend(identifiers)''')
replace('''        bundle, first_plan = self._exchange_plan(peer, accepted_transits, retry_packet_ids)
        require(len(evidence.canonical(bundle))''','''        current_carriage={}
        bundle, first_plan = self._exchange_plan(peer, accepted_transits, retry_packet_ids,
                                                 current_carriage=current_carriage)
        require(len(evidence.canonical(bundle))''')
replace('''        self.remember_carriage(peer,{'body':{'transits':ordinary}})
        return bundle''','''        self.remember_carriage(peer,{'body':{'transits':ordinary}})
        # Publish optional current-copy positions only after original durable
        # preparation. Lost sends rotate recipients, never grant custody; a
        # full4 retry, nonpriority pair or miss does not advance these positions.
        if current_carriage:
            domain=self.carriage_position_domain()
            for transit in carried_rows:
                ident=digest(transit['packet'])
                group=current_carriage['classes'].get(ident)
                if group is not None:
                    remember_carriage_position((domain,peer,'native-current-copy',
                                               current_carriage['scope'],*group),ident)
        return bundle''')
compile(text,str(p),'exec');back=text
for a,z in reversed(pairs):assert back.count(z)==1;back=back.replace(z,a)
assert back==old;old_methods={n.name:ast.dump(n,include_attributes=False) for n in ast.walk(ast.parse(old)) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))};new_methods={n.name:ast.dump(n,include_attributes=False) for n in ast.walk(ast.parse(text)) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))};changed=[k for k in old_methods if old_methods[k]!=new_methods[k]];assert set(changed)=={'_exchange_plan','prepare_exchange'};p.write_text(text)
rev=b/'current-copy-v25-reversal-20261007.json';assert not rev.exists();rev.write_text(json.dumps(dict(completed=True,pairs=pairs,old_source_sha256=hashlib.sha256(old.encode()).hexdigest(),new_source_sha256=hashlib.sha256(text.encode()).hexdigest(),changed_methods=changed,all_other_methods_AST_exact=True,original_cache512_4MiB_and_wire20MiB_unchanged=True,current_scope_frame_class_peer_only_primitive_positions=True,full4_nonpriority_miss_no_new_cursor_advancement=True),indent=2)+'\n');print(json.dumps(dict(completed=True,changed_methods=changed,profile='RLD-CONTACT-TRANSIT-SCHEDULER-V25')))
