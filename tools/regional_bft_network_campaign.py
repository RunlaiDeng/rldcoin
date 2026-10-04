#!/usr/bin/env python3
"""Actual TLS node lifecycle and autonomous regional votes; no message broker.

The controller starts/stops fixture processes and reads observations. It never
constructs a consensus vote, quorum, view certificate or finalization itself.
"""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

import interstellar_mesh as mesh
import interstellar_tcp as tcp
from regional_bft_campaign import Campaign as NativeCampaign
from regional_contact_campaign import public, seeds, save
from regional_bft_node import FORMAT
from regional_bft_retention import retained_body_present

# Cold startup authenticates every retained complete envelope before publishing
# current-process telemetry. This ground observation budget is separate from
# consensus phase deadlines and never substitutes for that authentication.
COLD_START_OBSERVATION_SECONDS = 300


class Campaign(NativeCampaign):
    def __init__(self, binary, root):
        super().__init__(binary,root)
        self.processes, self.logs, self.configs = {}, [], {}
        self.starts = 0
        self.observations = []
        self.node_ids, self.fingerprints = {}, {}
        held=[]
        self.ports={}
        try:
            for n in range(4):
                config={'format':mesh.VERSION,'state':str(self.root/f'mesh-{n}'),'network':self.currency,'contacts':[]}
                mesh.initialize(config['state'],self.currency,self.regions['earth'],f'validator-{n}')
                pin=tcp.public_tls_identity(config)
                self.node_ids[n],self.fingerprints[n]=pin['node_id'],pin['tls_cert_sha256']
                endpoint=socket.socket();endpoint.bind(('127.0.0.1',0));held.append(endpoint)
                self.ports[n]=endpoint.getsockname()[1]
        finally:
            for endpoint in held:endpoint.close()
        for n, seed in enumerate(seeds('earth')):
            # 0--1--2--3. Voters 1 and 3 must carry votes through voter 2.
            contacts=[{'peer':self.node_ids[j],'host':'127.0.0.1','port':self.ports[j],
                       'tls_cert_sha256':self.fingerprints[j]} for j in range(4) if abs(j-n)==1]
            mesh_config={'format':mesh.VERSION,'state':str(self.root/f'mesh-{n}'),'network':self.currency,'contacts':contacts}
            self.file(f'mesh-config-{n}',mesh_config)
            head_dir=self.root/f'caller-head-{n}';head_dir.mkdir(mode=0o700)
            head_path=head_dir/'head.json'
            save(head_path,{'format':FORMAT,'binding':{'currency':self.currency,'region':self.regions['earth'],'key':public(seed)},
                            'head':self.heads['earth',n],'pending':None,'outbox':None});head_path.chmod(0o600)
            config={'format':FORMAT,'state':str(self.root/f'bft-runtime-{n}'),'signer_dir':str(self.signer('earth',n)),
                    'head_file':str(head_path),'key_file':str(self.root/f'earth-{n}-key.json'),'key':public(seed),'miner':public(10),
                    'validators':[{'key':public(s),'node_id':self.node_ids[j]} for j,s in enumerate(seeds('earth'))],
                    'block_interval':1,'round_timeout':20,'stop_height':3}
            self.configs[n]=config
            path=self.file(f'bft-config-{n}',config);path.chmod(0o600)

    def invoke(self, command, success=True, helper=False):
        deadline=time.monotonic()+30
        while True:
            try:
                return super().invoke(command,success,helper)
            except ValueError as error:
                if success and ('would block' in str(error) or 'temporarily unavailable' in str(error)) and time.monotonic()<deadline:
                    time.sleep(0.025)
                    continue
                raise

    def observation(self,n):
        value=mesh.load(self.root/f'mesh-{n}/regional-contact-status.json',mesh.MAX_STATE)
        mesh.require(value['process_id']==self.processes[n].pid,'BFT network observation belongs to previous process')
        return value

    def wait(self, check, label, timeout=300):
        started=time.monotonic();deadline=started+timeout
        while time.monotonic()<deadline:
            for n, process in self.processes.items():
                mesh.require(process.poll() is None,'autonomous node exited: '+str(n))
            try:
                value=check()
                if value:
                    self.observations.append({'phase':label,'elapsed_seconds':round(time.monotonic()-started,3),
                                              'observation_bound_seconds':timeout})
                    return value
            except (OSError,ValueError,KeyError):pass
            time.sleep(0.1)
        summaries={}
        for n, process in self.processes.items():
            try:
                observed=self.observation(n)
                summaries[n]={'observation_available':True,
                              'native_observation_available':observed.get('native_observation_available'),
                              'errors':observed.get('errors',[]),
                              'process_exit_code':process.poll()}
            except (OSError,ValueError,KeyError) as error:
                # An old PID or absent telemetry is unknown, including in the
                # timeout diagnostic. Preserve the actual observation deadline.
                summaries[n]={'observation_available':False,'diagnostic':str(error),
                              'process_exit_code':process.poll()}
        raise ValueError('bounded ground observation deadline: '+label+' '+json.dumps(summaries))

    def start(self,n):
        mesh.require(n not in self.processes,'node is already running')
        log=(self.root/f'node-{n}.log').open('ab');self.logs.append(log)
        command=[str(self.binary),'--dir',str(self.node('earth',n)),'--authority',public(1),'--currency',self.currency,
                 '--mesh-config',str(self.root/f'mesh-config-{n}.json'),'--bft-config',str(self.root/f'bft-config-{n}.json'),
                 '--mesh-listen','127.0.0.1:'+str(self.ports[n]),'--transport-python',sys.executable,'--interval','0.25']
        self.processes[n]=subprocess.Popen(command,stdout=log,stderr=log)
        self.starts+=1
        self.wait(lambda:self.observation(n)['native_observation_available'],
                  'node startup '+str(n),COLD_START_OBSERVATION_SECONDS)

    def stop(self,n):
        process=self.processes.get(n)
        if process is not None:
            forced=False
            if process.poll() is None:
                try:
                    process.terminate()
                    try:process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        forced=True;process.kill();process.wait(timeout=10)
                except BaseException:
                    self._unclean_shutdown=True
                    raise
            # Keep ownership if either wait fails: an absent dictionary entry
            # must never falsely imply that a still-live process has stopped.
            self.processes.pop(n)
            if forced or process.returncode!=0:self._unclean_shutdown=True
            mesh.require(not forced and process.returncode==0,
                         'autonomous node did not stop cleanly: '+str(n))

    def cleanup(self):
        errors=[]
        for n in list(self.processes):
            try:self.stop(n)
            except BaseException as error:errors.append(f'{n}: {type(error).__name__}: {error}')
        for log in self.logs:
            try:log.close()
            except BaseException as error:errors.append(f'log: {type(error).__name__}: {error}')
        if errors:self._unclean_shutdown=True
        mesh.require(not errors,'owned process cleanup failed: '+json.dumps(errors))

    def reached(self, indices, height):
        values=[self.observation(n).get('consensus',{}).get('height') for n in indices]
        return all(type(value) is int and value>=height for value in values)

    def run(self):
        for n in (1,2,3):self.start(n)
        self.wait(lambda:self.reached((1,2,3),3),'three autonomous voters with initial leader offline')
        # Read actual proof/ledger; all signatures were produced by the running nodes.
        proof=self.cli('earth',1,'proof')
        mesh.require(all(s['bft']['prepared']['round']>=0 and len(s['bft']['committed']['votes'])>=3 for s in proof['snapshots']), 'native certificates missing')
        mesh.require(proof['snapshots'][0]['bft']['prepared']['round']>0,'offline leader did not require certified view change')
        mesh.require(self.cli('earth',0,'bft-status','--signer-dir',self.signer('earth',0))['records']==0,'offline validator signed')
        self.same_replicas('earth',(1,2,3))
        self.start(0)
        self.wait(lambda:self.reached((0,1,2,3),3),'offline replica catches up through TLS evidence')
        self.same_replicas('earth',(0,1,2,3))
        wallet=self.root/'owner-wallet'
        initialized=self.cli('earth',1,'wallet-init','--wallet-dir',wallet,'--owner',public(10))
        request={'owner':public(10),'inputs':None,'outputs':[{'owner':public(14),'amount':'30'}],
                 'remote':None,'fee':'1','valid_for_blocks':8}
        prepared=self.cli('earth',1,'wallet-prepare','--wallet-dir',wallet,'--expected-wallet-head',initialized['wallet_head'],
                          '--file',self.file('payment-request',request))
        key=self.file('owner-key',{'secret_key':(bytes([10])*32).hex()});key.chmod(0o600)
        signed=self.cli('earth',1,'wallet-sign','--wallet-dir',wallet,'--expected-wallet-head',prepared['wallet_head'],
                        '--file',self.file('reviewed-payment',prepared),'--review',prepared['review_commitment'],'--key-file',key)
        before=self.cli('earth',1,'status')['ledger']
        submitted=self.cli('earth',1,'bft-submit','--file',self.file('signed-commands',signed['commands']))
        mesh.require(submitted['queued'] and not submitted['block_included'] and self.cli('earth',1,'status')['ledger']==before,
                     'submission itself debited ledger')
        expected={'Submission':signed['commands']}
        self.wait(lambda:all(retained_body_present(self.root/f'bft-runtime-{n}/state.json',expected)
                            for n in range(4)), 'signed payment gossip before paused validators resume')
        retained={n:(self.root/f'caller-head-{n}/head.json').read_bytes() for n in range(4)}
        for n in range(4):self.stop(n)
        for n in range(4):
            head_path=self.root/f'caller-head-{n}/head.json'
            mesh.require(head_path.read_bytes()==retained[n],'clean shutdown changed retained caller head')
            head=mesh.load(head_path,8*1024*1024)
            native=self.cli('earth',n,'bft-status','--signer-dir',self.signer('earth',n))
            mesh.require(head['head']==native['head'] and head['pending'] is None and head['outbox'] is None,
                         'restart caller head differs from actual native journal')
        for n in range(4):
            config=dict(self.configs[n],stop_height=5)
            path=self.file(f'bft-config-{n}',config);path.chmod(0o600)
            self.start(n)
        self.wait(lambda:self.reached((0,1,2,3),5),'restart and autonomous wallet-command inclusion')
        self.same_replicas('earth',(0,1,2,3))
        final=self.cli('earth',1,'status')
        recipient=sum(int(c['payment']['amount']) for c in final['ledger']['coins'].values() if c['payment']['owner']==public(14))
        mesh.require(recipient==30,'actual recipient net amount differs')
        view=self.cli('earth',1,'wallet-view','--wallet-dir',wallet,'--expected-wallet-head',signed['wallet_head'])
        mesh.require(view['reserved_owned_outputs']=='0','native inclusion did not release only pending reservation')
        observations={n:self.observation(n) for n in range(4)}
        multihop=False
        with mesh.Node(mesh.load(self.root/'mesh-config-3.json',65536)) as node:
            for transit in node.state['messages'].values():
                packet,raw,_=mesh.transit_check(transit,node.network)
                frame,_=__import__('interstellar_transfer').inspect_frame(raw)
                if frame['kind']=='regional-bft' and packet['node_id']==self.node_ids[1] and packet['destination']==self.node_ids[3] and len(transit['hops'])==2:
                    multihop=True
        mesh.require(multihop,'consensus messages did not traverse two actual TLS relay hops')
        self.audit('autonomous TLS regional payment after certified leader change and restart')
        return {'format':'RLD-REGIONAL-BFT-AUTONOMOUS-GROUND-CAMPAIGN-V1','currency':self.currency,'implementation':self.implementation,
                'fixture_only':True,'live_rld':False,'ordinary_native_startup_used':True,'node_process_starts':self.starts,
                'initial_leader_offline':True,'three_native_voters_progressed':True,'controller_generated_consensus_messages':0,
                'controller_installed_checkpoints':0,'TLS_1_3_and_pinned_configured_neighbors':all(o['transport']['tcp']['encrypted'] for o in observations.values()),
                'actual_two_hop_consensus_carriage':True,'offline_replica_native_catchup':True,'external_heads_retained_on_restart':True,
                'signed_submission_did_not_debit':True,'actual_recipient_amount':'30','pending_wallet_reservation_after_inclusion':view['reserved_owned_outputs'],
                'replica_heights':[self.cli('earth',n,'status')['height'] for n in range(4)],'conservation':self.checks,
                'ground_round_timeout_seconds':self.configs[0]['round_timeout'],
                'observed_ground_phases':self.observations,
                'same_host_same_controller':True,'independent_operators_qualified':False,'complete_BFT_liveness_qualified':False,
                'BFT_reconfiguration_implemented':False,'external_monotonic_custody_qualified':False,'physical_interstellar_route_qualified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args();campaign=Campaign(args.binary,args.root)
    try:
        result=campaign.run();args.report.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result,indent=2))
    finally:campaign.cleanup()


if __name__=='__main__':main()
