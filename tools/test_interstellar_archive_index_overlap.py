"""Warm signed metadata cannot conceal a valid duplicate active transit."""
import copy
import tempfile
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
from test_interstellar_mesh import Fixture


class ArchiveIndexOverlapTests(unittest.TestCase):
    def test_warm_index_still_refuses_valid_active_archived_overlap_without_rewrite(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture=Fixture(directory)
            with fixture.node('earth') as node:
                ident=node.enqueue(fixture.frame(),node.id)
                transit=copy.deepcopy(node.state['messages'][ident])
                with patch.object(mesh,'ARCHIVE_HIGH_WATER',1):node.archive_completed()
                path=node.path
            with fixture.node('earth'):pass
            state=mesh.load(path,mesh.MAX_STATE)
            state['messages'][ident]=transit
            state['first_arrivals'].append(ident)
            mesh.atomic(path,state);before=path.read_bytes()
            with self.assertRaisesRegex(ValueError,'duplicate active/archived'):
                fixture.node('earth')
            self.assertEqual(path.read_bytes(),before)


if __name__=='__main__':unittest.main()
