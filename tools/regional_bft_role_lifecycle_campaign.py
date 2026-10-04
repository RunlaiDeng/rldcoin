#!/usr/bin/env python3
"""Five pinned same-host carriers, joining/continuing/departing, two role eras.

Run uses ordinary startup only. Setup pins public fixture keys and contacts;
controller calls which construct consensus/epoch proofs are counted separately.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import time

import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_bft_network_campaign import Campaign as NetworkCampaign
from regional_bft_joint_roles import FORMAT
from regional_contact_campaign import public, seeds
from interstellar_mesh_inspection import config_commitment


class Campaign(NetworkCampaign):
    def invoke(self, command, success=True, helper=False):
        command = list(command)
        if helper and command[-2:] == ['bootstrap', '--bft']:
            command[-1] = '--bft-joint-roles'
        if hasattr(self, 'controller_authority_calls') and not helper:
            actions = {'bft-sign', 'bft-quorum', 'bft-certify', 'bft-epoch-combine', 'install-epoch',
                       'bft-epoch-activate', 'bft-epoch-activate-observed',
                       'joint-ready-sign', 'joint-voter-init', 'finalize'}
            for value in command:
                if str(value) in actions:
                    self.controller_authority_calls += 1
                    break
        return super().invoke(command, success, helper)

    def __init__(self, binary, root, heights=(1, 3), stop_height=4):
        mesh.require(len(heights)==2 and 1 <= heights[0] < heights[1] <= 63 and 1 <= stop_height <= 63,
                     'two ordered role boundaries and bounded final height required')
        super().__init__(binary, root)
        self.controller_authority_calls = 0
        self.cli('earth', 4, 'init', '--bootstrap', self.bootstrap, '--region', 'earth')
        mesh.initialize(self.root/'mesh-4', self.currency, self.regions['earth'], 'joining-validator-4')
        config = dict(format=mesh.VERSION, state=str(self.root/'mesh-4'), network=self.currency, contacts=[])
        pin = tcp.public_tls_identity(config)
        self.node_ids[4], self.fingerprints[4] = pin['node_id'], pin['tls_cert_sha256']
        with socket.socket() as endpoint:
            endpoint.bind(('127.0.0.1', 0))
            self.ports[4] = endpoint.getsockname()[1]
        old = seeds('earth')
        self.memberships = [{seed:n for n, seed in enumerate(old)},
                            {62:0, old[1]:1, old[2]:2, old[3]:3},
                            {62:0, old[2]:2, old[3]:3, 63:4}]
        self.heights = list(heights)
        for seed in (62, 63):
            self.file(f'role-key-{seed}', dict(secret_key=(bytes([seed])*32).hex())).chmod(0o600)
        mappings = [[dict(key=public(seed), node_id=self.node_ids[carrier])
                     for seed, carrier in sorted(m.items(), key=lambda pair: public(pair[0]))]
                    for m in self.memberships]
        for n in range(5):
            contacts = [dict(peer=self.node_ids[j], host='127.0.0.1', port=self.ports[j],
                             tls_cert_sha256=self.fingerprints[j]) for j in range(5) if abs(j-n)==1]
            self.file(f'mesh-config-{n}', dict(format=mesh.VERSION, state=str(self.root/f'mesh-{n}'),
                                              network=self.currency, contacts=contacts))
            initial = None
            if n in (1, 2, 3):
                path = self.root/f'caller-head-{n}/head.json'
                mesh.atomic(path, dict(mesh.load(path, 8*1024*1024), format=FORMAT))
                initial = dict(key=public(old[n]), key_file=str(self.root/f'earth-{n}-key.json'),
                               signer_dir=str(self.signer('earth', n)), head_file=str(path))
            handoffs = []
            for number in (1, 2):
                local = next((s for s, carrier in self.memberships[number].items() if carrier == n), None)
                slot = None
                if local is not None:
                    voter_caller = self.root/f'role-voter-caller-{number}-{n}'
                    ready_caller = self.root/f'role-ready-caller-{number}-{n}'
                    voter_caller.mkdir(mode=0o700)
                    ready_caller.mkdir(mode=0o700)
                    binding = dict(currency=self.currency, region=self.regions['earth'], key=public(local))
                    mesh.atomic(voter_caller/'head.json', dict(format=FORMAT, binding=binding, head=None,
                                                              pending=None, outbox=None, initialization=None))
                    mesh.atomic(ready_caller/'head.json', dict(format=FORMAT, binding=dict(binding, role='New', number=number),
                                  head=None, scope=None, native_binding=None, initialization=None, pending=None, outbox=None))
                    keyfile = self.root/f'role-key-{local}.json' if local in (62, 63) else self.root/f'earth-{old.index(local)}-key.json'
                    slot = dict(key=public(local), key_file=str(keyfile), signer_dir=str(self.root/f'role-voter-{number}-{n}'),
                                head_file=str(voter_caller/'head.json'), ready_dir=str(self.root/f'role-ready-{number}-{n}'),
                                ready_head=str(ready_caller/'head.json'))
                handoffs.append(dict(select_height=self.heights[number-1], validators=mappings[number], slot=slot))
            self.configs[n] = dict(format=FORMAT, state=str(self.root/f'bft-runtime-{n}'), miner=public(10),
                                  validators=mappings[0], block_interval=1, round_timeout=20, stop_height=stop_height,
                                  initial_slot=initial, handoffs=handoffs)
            self.file(f'bft-config-{n}', self.configs[n]).chmod(0o600)
        # Record public inspection trust during fresh setup, separately from
        # the stores later inspected. Cold inspection never reads private keys
        # or derives trust from a retained advertisement/state.
        anchors=dict(format='RLD-ROLE-MESH-INSPECTION-ANCHORS-V1',network=self.currency,
                     role_validators=mappings,nodes={})
        for n in range(5):
            config=mesh.load(self.root/f'mesh-config-{n}.json',65536)
            with mesh.Node(config) as node:
                anchors['nodes'][str(n)]=dict(public_key=node.key.public_key().public_bytes(
                    mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex(),node_id=node.id,network=self.currency,
                    config_sha256=config_commitment(config))
        self.inspection_anchors_path=self.file('mesh-inspection-anchors',anchors)
        self.inspection_anchors_sha256=hashlib.sha256(self.inspection_anchors_path.read_bytes()).hexdigest()

    def reached(self, indices, height):
        values=[self.observation(n).get('consensus',{}).get('height') for n in indices]
        return all(type(value) is int and value >= height for value in values)

    def run(self):
        started = time.monotonic()
        for n in range(5):
            self.start(n)
        self.wait(lambda: self.reached(tuple(range(5)), 4), 'five carriers and two native role handoffs', timeout=600)
        self.same_replicas('earth', tuple(range(5)))
        current = self.cli('earth', 2, 'bft-context')
        mesh.require(current['active_epoch_proof']['statement']['number'] == 2, 'second role activation absent')
        for n in range(5):
            observation = self.observation(n)['consensus']
            mesh.require(observation['joint_active_slot'] == 2, 'carrier did not observe second actual native era')
            mesh.require(observation['autonomous_signing_enabled'] == (n != 1), 'departing/joining role status differs')
        mesh.require(self.controller_authority_calls == 0, 'controller constructed authority during ordinary lifecycle')
        self.cleanup()
        return dict(format='RLD-ROLE-LIFECYCLE-GROUND-CAMPAIGN-V1', completed=True, fixture_only=True, live_rld=False,
                    implementation=self.implementation, currency=self.currency, carriers=5, configured_handoffs=2,
                    joining_only_carriers=[0, 4], departing_only_after_second=[1], continuing_carriers=[2, 3],
                    initial_missing_old_voter=0, same_host=True, cross_host_qualified=False,
                    controller_authority_calls=self.controller_authority_calls, owned_process_cleanup_verified=True,
                    native_active_epoch=current['context']['epoch'], final_height=4,
                    duration_seconds=round(time.monotonic()-started, 3), observations=self.observations,
                    fresh_full_fault_profile_completed=False, stopped_cold_verification_completed=False,
                    independent_custody_qualified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    campaign = None
    try:
        campaign = Campaign(args.binary, args.root)
        result = campaign.run()
    except BaseException as error:
        result = dict(format='RLD-ROLE-LIFECYCLE-GROUND-CAMPAIGN-V1', completed=False, fixture_only=True,
                      live_rld=False, failure=f'{type(error).__name__}: {error}')
        if campaign is not None:
            result.update(currency=campaign.currency, implementation=campaign.implementation,
                          controller_authority_calls=campaign.controller_authority_calls, observations=campaign.observations)
        raise
    finally:
        if campaign is not None:
            campaign.cleanup()
            result['owned_process_cleanup_verified'] = not campaign.processes
            result['mesh_inspection_anchors_sha256'] = campaign.inspection_anchors_sha256
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(result, indent=2)+'\n')


if __name__ == '__main__':
    main()
