"""Native observation and explicit endpoint refusal boundaries, no custody."""
import copy
import unittest
from regional_paged_fault_prepared import native_matches, ports_valid


class Boundaries(unittest.TestCase):
    def test_later_native_observation_cannot_replace_retained_checkpoint(self):
        retained=dict(history_head='1'*64,currency='2'*64,region='3'*64,height=8,
            tip='4'*64,state='5'*64,finality='6'*64,validator_epoch=None,
            logical_native_replay_complete=True,fixture_only=True,live_rld=False,
            independent_latest_state_anchor_qualified=False)
        native_matches(retained,retained)
        for field,value in [('history_head','9'*64),('state','9'*64),('height',9),
            ('finality','9'*64),('validator_epoch','9'*64),('logical_native_replay_complete',False),
            ('fixture_only',False),('live_rld',True),('independent_latest_state_anchor_qualified',True)]:
            changed=copy.deepcopy(retained);changed[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                native_matches(changed,retained)

    def test_ports_are_explicit_unique_and_never_bool_or_advertised_values(self):
        ports_valid(tuple(range(42000,42012)),(42100,42101))
        for ports,relays in [(tuple(range(42000,42011)),(42100,42101)),
            (tuple(range(42000,42012)),(42000,42101)),
            ((True,*range(42001,42012)),(42100,42101)),
            (tuple(range(42000,42012)),(42100,'42101')),
            (list(range(42000,42012)),(42100,42101))]:
            with self.assertRaises(ValueError):ports_valid(ports,relays)


if __name__=='__main__':unittest.main()
