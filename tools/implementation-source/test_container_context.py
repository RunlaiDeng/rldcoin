"""Regression: the node builder's local COPY inputs contain the named source set.

This does not execute Docker, resolve base images or test Linux runtime behavior.
"""
import shlex
import shutil
import tempfile
import unittest
from pathlib import Path
from verify import capture

class ContainerSourceTests(unittest.TestCase):
    def test_node_builder_copy_inventory_matches_source(self):
        root=Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix='rld-container-source-check-') as tmp:
            staged=Path(tmp).resolve()
            for line in (root/'Dockerfile.node').read_text().splitlines():
                if line.startswith('FROM ') and ' AS runner' in line:break
                if not line.startswith('COPY '):continue
                words=shlex.split(line)
                # Cargo's external registry configuration is outside the named set.
                if words[-1].startswith('/'):continue
                destination=staged/words[-1]
                self.assertTrue(destination.resolve().is_relative_to(staged))
                destination.mkdir(parents=True,exist_ok=True)
                for source in words[1:-1]:
                    src=root/source
                    self.assertTrue(src.resolve().is_relative_to(root))
                    if src.is_dir():
                        shutil.copytree(src,destination,dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('target','__pycache__','.DS_Store'))
                    else:shutil.copy2(src,destination/src.name)
            self.assertEqual(capture(root),capture(staged))

if __name__=='__main__':unittest.main()
