from pathlib import Path
r=Path.cwd();assert r==Path('/Users/galaxy/GitHub/rldcoin');p=r/'tools/test_interstellar_mesh.py';s=p.read_text();marker='    def test_completed_archive_reopens_exact_frame_and_keeps_scoped_receipt(self):\n';assert s.count(marker)==1
new='''    def test_archive_cold_streamed_bytes_are_exact_and_authentication_stays_required(self):
        ident=self.completed_local()[0]
        with self.f.node('earth') as node,patch.object(mesh,'ARCHIVE_HIGH_WATER',1):
            self.assertEqual(node.archive_completed(),1)
            body=copy.deepcopy(node.state['archives'][ident]['body'])
        canonical=evidence.canonical
        def small_metadata(value):
            if (isinstance(value,dict) and
                    ((set(value)=={'format','network','node_id','frame'} and isinstance(value['frame'],str))
                     or (set(value)=={'format','network','node_id','packet_id','transit','receipt'}
                         and value['transit'] is not None))):
                raise AssertionError('full archive frame canonical encoding repeated')
            return canonical(value)
        with self.f.node('earth') as node:
            with mesh._verified_transits_lock:mesh._verified_transits.clear()
            with patch.object(evidence,'canonical',side_effect=small_metadata):
                complete=node.archived(ident)
            encoded=canonical(complete)
            self.assertEqual((evidence.hashlib.sha256(encoded).hexdigest(),len(encoded)),
                             (body['expanded_sha256'],body['expanded_size_bytes']))
            for code in range(128):
                trial=copy.deepcopy(complete)
                trial['transit']['packet']['body']['frame']='AA'+chr(code)+'BB'
                raw=canonical(trial)
                self.assertEqual(mesh.frame_digest.archive_commitment(trial),
                                 (evidence.hashlib.sha256(raw).hexdigest(),len(raw)))
            for trial in ({},[],dict(complete,transit=None),
                          dict(complete,transit={'packet':{'body':{'frame':'雪\\\\"'}}}),
                          dict(complete,transit={'packet':{'body':{'frame':12}}})):
                raw=canonical(trial)
                self.assertEqual(mesh.frame_digest.archive_commitment(trial),
                                 (evidence.hashlib.sha256(raw).hexdigest(),len(raw)))
            archive=node.archive_root/(body['frame_object']['file_id']+'.json')
            original=archive.read_bytes();changed=bytearray(original);changed[-3]^=1;archive.write_bytes(changed)
            with self.assertRaisesRegex(ValueError,'frame bytes differ'):node.archived(ident)
            self.assertEqual(archive.read_bytes(),bytes(changed))
            archive.write_bytes(original)
            node.state['archives'][ident]['signature']='0'*128
            with self.assertRaisesRegex(ValueError,'signature'):node.archived(ident)

'''
compile(s.replace(marker,new+marker),str(p),'exec');assert 'def test_archive_cold_streamed_bytes_are_exact' not in s;p.write_text(s.replace(marker,new+marker))
b=r/'tmp/default-relay-20260930';old=(b/'check-carriage-hint-pressure-ground-20261006.py').read_text();new=old.replace("'hint-pressure-delivery-v19')","'hint-pressure-delivery-v19','archive-stream-baseline-v19','archive-stream-related-v20')");assert new!=old;path=b/'check-archive-stream-ground-v20-20261006.py';assert not path.exists();path.write_text(new)
