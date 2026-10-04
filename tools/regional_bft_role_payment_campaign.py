#!/usr/bin/env python3
"""Ordinary five-carrier role handoffs and actual-owner payments in three eras.

Fresh no-value fixture only. The controller owns wallet signing and process
pauses, never consensus signing, handoff approvals or proof installation.
"""
import argparse
import json
from pathlib import Path
import time

import interstellar_mesh as mesh
from regional_contact_campaign import public
from regional_bft_role_lifecycle_campaign import Campaign as Lifecycle

FORMAT = 'RLD-ROLE-PAYMENT-GROUND-CAMPAIGN-V1'
PAYMENTS = ((10, 14, 30, 3, 0), (14, 15, 20, 7, 1), (15, 16, 10, 11, 2))


class Campaign(Lifecycle):
    def __init__(self, binary, root):
        super().__init__(binary, root, heights=(4, 8), stop_height=3)
        self.payments = []

    def phase(self, height, label):
        mesh.require(not self.processes, 'phase starts only after owned processes stop')
        for n in range(5):
            self.configs[n]['stop_height'] = height
            self.file(f'bft-config-{n}', self.configs[n]).chmod(0o600)
            self.start(n)
        self.wait(lambda: self.reached(tuple(range(5)), height), label, timeout=600)
        self.cleanup()
        self.same_replicas('earth', tuple(range(5)))
        mesh.require(self.cli('earth', 2, 'status')['height']==height, 'paused exact native height differs')

    def offer(self, owner, recipient, amount, height, era):
        before = self.cli('earth', 2, 'status')
        context = self.cli('earth', 2, 'bft-context')
        active = context['active_epoch_proof']
        mesh.require(before['height']==height and (active is None if era==0 else active['statement']['number']==era),
                     'wallet signing is not at intended actual native era')
        wallet = self.root/f'payment-wallet-{era}'
        caller = self.root/f'payment-caller-{era}'
        caller.mkdir(mode=0o700)
        initial = self.cli('earth', 2, 'wallet-init', '--wallet-dir', wallet, '--owner', public(owner))
        binding = dict(currency=self.currency, region=self.regions['earth'], owner=public(owner))
        head = dict(format=FORMAT, binding=binding, head=initial['wallet_head'], pending=None)
        mesh.atomic(caller/'head.json', head)
        request = dict(owner=public(owner), inputs=None, outputs=[dict(owner=public(recipient), amount=str(amount))],
                       remote=None, fee='1', valid_for_blocks=8)
        prepared = self.cli('earth', 2, 'wallet-prepare', '--wallet-dir', wallet,
                            '--expected-wallet-head', head['head'], '--file', self.file(f'payment-request-{era}', request))
        mesh.require(prepared['draft']['pin']['height']==height and prepared['draft']['pin']['epoch']==context['context']['epoch'],
                     'actual owner review has different native height/era')
        head['pending'] = prepared
        mesh.atomic(caller/'head.json', head)
        key = self.file(f'payment-owner-key-{era}', dict(secret_key=(bytes([owner])*32).hex()))
        key.chmod(0o600)
        signed = self.cli('earth', 2, 'wallet-sign', '--wallet-dir', wallet, '--expected-wallet-head', head['head'],
                          '--file', self.file(f'payment-review-{era}', prepared), '--review', prepared['review_commitment'], '--key-file', key)
        head.update(head=signed['wallet_head'], pending=None, intent_id=signed['intent_id'])
        mesh.atomic(caller/'head.json', head)
        commands = self.file(f'payment-commands-{era}', signed['commands'])
        submitted = self.cli('earth', 2, 'bft-submit', '--file', commands)
        mesh.require(submitted['queued'] and not submitted['block_included']
                     and self.cli('earth', 2, 'status')==before, 'wallet signature/submission changed native ledger')
        view = self.cli('earth', 2, 'wallet-view', '--wallet-dir', wallet, '--expected-wallet-head', head['head'])
        mesh.require(int(view['reserved_owned_outputs'])==int(prepared['draft']['selected_input_total'])>0,
                     'actual owner inputs were not separately reserved')
        self.payments.append(dict(era=era, owner=public(owner), recipient=public(recipient), amount=str(amount), fee='1',
                                  signing_height=height, intent_id=signed['intent_id'],
                                  selected_input_total=prepared['draft']['selected_input_total'],
                                  signature_and_submission_did_not_debit=True))

    def run(self):
        started = time.monotonic()
        for owner, recipient, amount, height, era in PAYMENTS:
            self.phase(height, f'ordinary native era {era} before owner payment')
            self.offer(owner, recipient, amount, height, era)
        self.phase(14, 'third-era payment inclusion and recipient maturity')
        state = self.cli('earth', 2, 'status')
        for row in self.payments:
            era = row['era']
            head = mesh.load(self.root/f'payment-caller-{era}/head.json', 8*1024*1024)
            view = self.cli('earth', 2, 'wallet-view', '--wallet-dir', self.root/f'payment-wallet-{era}',
                            '--expected-wallet-head', head['head'])
            mesh.require(view['reserved_owned_outputs']=='0' and len(view['signed'])==1
                         and view['signed'][0]['intent_id']==row['intent_id'] and view['signed'][0]['state']=='INCLUDED_IN_LOCAL_LEDGER',
                         'owner payment missing native inclusion or still reserved')
            row['native_included'] = True
        for owner, amount in ((14, 9), (15, 9), (16, 10)):
            coins = [c for c in state['ledger']['coins'].values() if c['payment']['owner']==public(owner)]
            mesh.require(sum(int(c['payment']['amount']) for c in coins)==amount and
                         all(c['mature']<=state['height'] for c in coins), 'recipient current native balance/maturity differs')
        ledger = state['ledger']
        recipient_wallet = self.root/'payment-recipient-wallet'
        recipient_caller = self.root/'payment-recipient-caller'
        recipient_caller.mkdir(mode=0o700)
        initial = self.cli('earth', 2, 'wallet-init', '--wallet-dir', recipient_wallet, '--owner', public(16))
        mesh.atomic(recipient_caller/'head.json', dict(format=FORMAT,
                    binding=dict(currency=self.currency,region=self.regions['earth'],owner=public(16)),
                    head=initial['wallet_head'],pending=None))
        recipient_view = self.cli('earth', 2, 'wallet-view', '--wallet-dir', recipient_wallet,
                                  '--expected-wallet-head', initial['wallet_head'])
        mesh.require(recipient_view['available']=='10' and recipient_view['ledger']['immature']=='0'
                     and recipient_view['reserved_owned_outputs']=='0', 'final recipient native spendability differs')
        liquid = sum(int(c['payment']['amount']) for c in ledger['coins'].values())
        mesh.require(int(ledger['minted'])==liquid and not ledger['exports'] and not ledger['imports'], 'native conservation differs')
        mesh.require(self.controller_authority_calls==0 and self.starts==20 and not self.processes,
                     'ordinary authority/process lifecycle differs')
        return dict(format=FORMAT, completed=True, fixture_only=True, live_rld=False, implementation=self.implementation,
                    currency=self.currency, carriers=5, configured_handoffs=2, select_heights=self.heights, final_height=14,
                    owner_payments=self.payments, owner_signing_eras=[0,1,2], node_process_starts=self.starts,
                    final_recipient_native_available='10',
                    owned_process_cleanup_verified=True, controller_authority_calls=0,
                    ordinary_native_startup_used=True, minted=ledger['minted'], liquid=str(liquid), conserved=True,
                    observations=self.observations, duration_seconds=round(time.monotonic()-started,3),
                    same_host=True, cross_host_qualified=False, fresh_full_fault_profile_completed=False,
                    stopped_cold_verification_completed=False, independent_custody_qualified=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'root', 'report'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args();campaign=None;primary_error=None
    try:
        campaign=Campaign(args.binary,args.root);result=campaign.run()
    except BaseException as error:
        primary_error=error
        result=dict(format=FORMAT,completed=False,fixture_only=True,live_rld=False,failure=f'{type(error).__name__}: {error}')
        if campaign is not None:
            result.update(currency=campaign.currency,implementation=campaign.implementation,
                          controller_authority_calls=campaign.controller_authority_calls,observations=campaign.observations,
                          owner_payments=campaign.payments)
        raise
    finally:
        cleanup_error=None
        if campaign is not None:
            try:campaign.cleanup()
            except BaseException as error:
                cleanup_error=error;result.update(completed=False,cleanup_failure=f'{type(error).__name__}: {error}')
                if primary_error is None:result['failure']=result['cleanup_failure']
            result['owned_process_cleanup_verified']=not campaign.processes
            result['owned_process_shutdown_clean']=cleanup_error is None and not getattr(campaign,'_unclean_shutdown',False)
            if not result['owned_process_shutdown_clean'] and cleanup_error is None:
                cleanup_error=ValueError('an earlier owned process shutdown was unclean')
                result.update(completed=False,cleanup_failure=f'ValueError: {cleanup_error}')
                if primary_error is None:result['failure']=result['cleanup_failure']
            result['mesh_inspection_anchors_sha256']=campaign.inspection_anchors_sha256
        args.report.parent.mkdir(parents=True,exist_ok=True)
        args.report.write_text(json.dumps(result,indent=2)+'\n')
        if cleanup_error is not None and primary_error is None:raise cleanup_error


if __name__=='__main__':main()
