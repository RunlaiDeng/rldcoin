"""Actual native head checks remain mandatory after readonly tick deferral."""
from pathlib import Path
import unittest
from unittest.mock import patch

import interstellar_mesh as mesh
import test_regional_bft_joint_roles_lifecycle as lifecycle
from verify_regional_bft_sustained import files


class RoleTickHeadTests(unittest.TestCase):
    setUp = lifecycle.RoleLifecycleTests.setUp
    tearDown = lifecycle.RoleLifecycleTests.tearDown
    open = lifecycle.RoleLifecycleTests.open
    close = lifecycle.RoleLifecycleTests.close
    slot = lifecycle.RoleLifecycleTests.slot
    activation = lifecycle.RoleLifecycleTests.activation

    def installed(self):
        self.activation()
        runtime = self.runtimes[0]
        runtime.joint.advance()
        runtime.observe()
        runtime.stop_height = runtime.state['height']
        return runtime

    def custody(self, runtime):
        paths = [runtime.native.ledger, runtime.signer, runtime.head_path.parent]
        for handoff in self.c.configs[0]['handoffs']:
            slot = handoff['slot']
            if slot is not None and Path(slot['ready_dir']).exists():
                paths.append(Path(slot['ready_dir']))
        return {str(path): files(path) for path in paths}

    def test_installed_tick_uses_one_actual_native_voter_check_without_custody_change(self):
        runtime = self.installed()
        before = self.custody(runtime)
        native = runtime.native.call
        actions = []
        def observe(action, *args):
            actions.append(action)
            return native(action, *args)
        with patch.object(runtime.native, 'call', side_effect=observe):
            result = runtime.tick()
        self.assertEqual(actions.count('bft-status'), 1)
        self.assertNotIn('bft-sign', actions)
        self.assertEqual(result['joint_active_slot'], 1)
        self.assertEqual(before, self.custody(runtime))

    def test_installed_tick_refuses_changed_caller_head_before_any_signing(self):
        runtime = self.installed()
        runtime.save_head(dict(runtime.head, head='00'*32))
        before = self.custody(runtime)
        native = runtime.native.call
        actions = []
        def observe(action, *args):
            actions.append(action)
            return native(action, *args)
        with patch.object(runtime.native, 'call', side_effect=observe):
            with self.assertRaisesRegex(ValueError, 'separately retained caller head'):
                runtime.tick()
        self.assertEqual(actions.count('bft-status'), 1)
        self.assertNotIn('bft-sign', actions)
        self.assertNotIn('joint-ready-sign', actions)
        self.assertEqual(before, self.custody(runtime))

    def test_pending_handoff_refuses_changed_head_before_fence_or_readiness_creation(self):
        runtime = self.open(1)
        runtime.save_head(dict(runtime.head, head='00'*32))
        slot = self.slot(1)
        before = files(self.c.root)
        with self.assertRaisesRegex(ValueError, 'separately retained caller head'):
            runtime.tick()
        self.assertFalse(Path(slot['ready_dir']).exists())
        self.assertFalse(Path(slot['signer_dir']).exists())
        self.assertEqual(before, files(self.c.root))

    def test_standalone_role_tick_keeps_its_immediate_native_head_check(self):
        runtime = self.installed()
        runtime.save_head(dict(runtime.head, head='00'*32))
        before = self.custody(runtime)
        with self.assertRaisesRegex(ValueError, 'separately retained caller head'):
            runtime.joint.tick()
        self.assertEqual(before, self.custody(runtime))


if __name__ == '__main__':
    unittest.main()
