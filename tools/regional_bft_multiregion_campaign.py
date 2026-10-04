#!/usr/bin/env python3
"""Twelve ordinary TLS nodes autonomously settle a three-region value cycle.

The controller operates processes, submits owner-signed commands and reads
observations. It cannot sign votes, carry proofs or install native checkpoints.
Private fixture directories and generated mesh/TLS keys must never be published.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import sys
import time

import interstellar_mesh as mesh
import interstellar_tcp as tcp
import interstellar_transfer as wire
from regional_bft_campaign import Campaign as NativeCampaign, NAMES
from regional_bft_network_campaign import Campaign as NetworkCampaign
from regional_bft_node import FORMAT
from regional_bft_retention import retained_body_present
from regional_contact_campaign import public, seeds, save
from interstellar_mesh_inspection import config_commitment


class Campaign(NetworkCampaign):
    def __init__(self, binary, root):
        NativeCampaign.__init__(self,binary,root)
        self.processes,self.logs,self.configs={},[],{}
        self.starts=0
        self.observations=[]
        self.node_ids,self.fingerprints,self.ports={},{},{}
        held=[]
        try:
            for name in NAMES:
                for n in range(4):
                    key=(name,n)
                    config={'format':mesh.VERSION,'state':str(self.mesh_root(key)),
                            'network':self.currency,'contacts':[]}
                    mesh.initialize(config['state'],self.currency,self.regions[name],f'{name}-validator-{n}')
                    pin=tcp.public_tls_identity(config)
                    self.node_ids[key],self.fingerprints[key]=pin['node_id'],pin['tls_cert_sha256']
                    endpoint=socket.socket();endpoint.bind(('127.0.0.1',0));held.append(endpoint)
                    self.ports[key]=endpoint.getsockname()[1]
        finally:
            for endpoint in held:endpoint.close()
        for name in NAMES:
            for n,seed in enumerate(seeds(name)):
                key=(name,n)
                # Each local region is 0--1--2--3; only the adjacent gateway
                # pairs Earth-1--Proxima-1--Andromeda-1 span regions.
                adjacent=[(name,j) for j in range(4) if abs(j-n)==1]
                if n==1:
                    index=NAMES.index(name)
                    adjacent += [(other,1) for j,other in enumerate(NAMES) if abs(j-index)==1]
                contacts=[{'peer':self.node_ids[j],'host':'127.0.0.1','port':self.ports[j],
                           'tls_cert_sha256':self.fingerprints[j]} for j in adjacent]
                self.file(f'mesh-config-{name}-{n}',{'format':mesh.VERSION,'state':str(self.mesh_root(key)),
                                                   'network':self.currency,'contacts':contacts})
                head_dir=self.root/f'caller-head-{name}-{n}';head_dir.mkdir(mode=0o700)
                head_path=head_dir/'head.json'
                save(head_path,{'format':FORMAT,'binding':{'currency':self.currency,'region':self.regions[name],
                            'key':public(seed)},'head':self.heads[key],'pending':None,'outbox':None})
                head_path.chmod(0o600)
                config={'format':FORMAT,'state':str(self.root/f'bft-runtime-{name}-{n}'),
                        'signer_dir':str(self.signer(name,n)),'head_file':str(head_path),
                        'key_file':str(self.root/f'{name}-{n}-key.json'),'key':public(seed),
                        'miner':public(10 if name=='earth' else 20),
                        'validators':[{'key':public(s),'node_id':self.node_ids[name,j]}
                                      for j,s in enumerate(seeds(name))],
                        'block_interval':1,'round_timeout':60,'stop_height':3 if name=='earth' else 0}
                self.configs[key]=config
                self.file(f'bft-config-{name}-{n}',config).chmod(0o600)
        self.pin_inspection_anchors()
        self.progress('initialized twelve independent native stores')

    def pin_inspection_anchors(self):
        path=self.root/'mesh-inspection-anchors.json'
        mesh.require(not path.exists() and not path.is_symlink(),'retain existing setup inspection anchors')
        anchors=dict(format='RLD-MULTIREGION-MESH-INSPECTION-ANCHORS-V1',network=self.currency,nodes={})
        for name in NAMES:
            for key in self.region_keys(name):
                config=mesh.load(self.root/f'mesh-config-{name}-{key[1]}.json',65536)
                with mesh.Node(config) as node:
                    mesh.require(node.id==self.node_ids[key],'setup carrier identity differs from configured pin')
                    anchors['nodes'][f'{name}-{key[1]}']=dict(public_key=node.key.public_key().public_bytes(
                        mesh.Encoding.Raw,mesh.PublicFormat.Raw).hex(),node_id=node.id,network=self.currency,
                        config_sha256=config_commitment(config))
        mesh.atomic(path,anchors)
        self.inspection_anchors_sha256=hashlib.sha256(path.read_bytes()).hexdigest()

    def cli(self, name, n, *args, success=True):
        mesh.require(args and args[0] not in {'bft-sign','bft-quorum','bft-timeout-certificate','bft-certify',
                     'finalize','mine','accept','contact-apply','contact-fulfill','bft-sync'},
                     'controller attempted to produce or install protocol progress')
        return NativeCampaign.cli(self,name,n,*args,success=success)

    def mesh_root(self,key):
        return self.root/f'mesh-{key[0]}-{key[1]}'

    def progress(self,phase):
        mesh.atomic(self.root/'campaign-progress.json',{'phase':phase,'fixture_only':True,
                    'currency':self.currency,'implementation':self.implementation,
                    'native_cli_calls':self.calls,'node_process_starts':self.starts,
                    'observed_ground_phases':self.observations})
        print(json.dumps({'phase':phase}),flush=True)

    def observation(self,key):
        value=mesh.load(self.mesh_root(key)/'regional-contact-status.json',mesh.MAX_STATE)
        mesh.require(value['process_id']==self.processes[key].pid,'observation belongs to previous process')
        return value

    def wait(self,check,label,timeout=600):
        started=time.monotonic();deadline=started+timeout
        self.progress('waiting: '+label)
        while time.monotonic()<deadline:
            for key,process in self.processes.items():
                mesh.require(process.poll() is None,'autonomous node exited: '+str(key))
            try:
                value=check()
                if value:
                    self.observations.append({'phase':label,'elapsed_seconds':round(time.monotonic()-started,3),
                                              'observation_bound_seconds':timeout})
                    self.progress('verified: '+label)
                    return value
            except (OSError,ValueError,KeyError):pass
            time.sleep(0.2)
        summaries={}
        for key,process in self.processes.items():
            try:
                observed=self.observation(key)
                summaries[str(key)]=dict(observation_available=True,
                    native_observation_available=observed.get('native_observation_available'),
                    errors=observed.get('errors',[]),process_exit_code=process.poll())
            except (OSError,ValueError,KeyError) as error:
                summaries[str(key)]=dict(observation_available=False,diagnostic=str(error),
                                         process_exit_code=process.poll())
        raise ValueError('bounded ground observation deadline: '+label+' '+json.dumps(summaries))

    def start(self,key):
        name,n=key
        mesh.require(key not in self.processes,'node is already running')
        log=(self.root/f'node-{name}-{n}.log').open('ab');self.logs.append(log)
        command=[str(self.binary),'--dir',str(self.node(name,n)),'--authority',public(1),'--currency',self.currency,
                 '--mesh-config',str(self.root/f'mesh-config-{name}-{n}.json'),
                 '--bft-config',str(self.root/f'bft-config-{name}-{n}.json'),
                 '--mesh-listen','127.0.0.1:'+str(self.ports[key]),'--transport-python',sys.executable,'--interval','0.25']
        self.processes[key]=subprocess.Popen(command,stdout=log,stderr=log)
        self.starts+=1
        self.wait(lambda:self.observation(key)['native_observation_available'],f'node startup {name}-{n}',60)

    def region_keys(self,name):
        return [(name,n) for n in range(4)]

    def cleanup(self):
        NetworkCampaign.cleanup(self)

    def reached_region(self,name,height):
        values=[(self.observation(key).get('consensus') or {}).get('height')
                for key in self.region_keys(name)]
        return all(type(value) is int and value==height for value in values)

    def resume(self,name,height):
        for key in self.region_keys(name):self.stop(key)
        for key in self.region_keys(name):
            config=dict(self.configs[key],stop_height=height)
            # The independently stored caller head survives process operation
            # byte-for-byte. Changing the local test cap never adopts a head.
            head_path=Path(config['head_file']);before=head_path.read_bytes()
            self.file(f'bft-config-{name}-{key[1]}',config).chmod(0o600)
            mesh.require(head_path.read_bytes()==before,'restart modified retained caller head')
            self.configs[key]=config
        for key in self.region_keys(name):self.start(key)
        self.wait(lambda:self.reached_region(name,height),f'{name} autonomous certified height {height}')
        self.same_replicas(name,range(4))
        self.audit(f'{name}: autonomous certified height {height}')

    def pending(self,name,eid):
        for key in self.region_keys(name):
            observed=self.observation(key)
            value=observed['native_observation']
            if observed.get('native_observation_available') is not True or value is None:return False
            records=[r for r in value['contacts'] if r['export']==eid]
            if not records or not all(r['evidence_verified'] and not r['import_accepted'] for r in records):return False
        return True

    def submit_export(self,name,owner,destination,recipient,gross,destination_fee):
        wallet=self.root/f'{name}-owner-{owner}'
        initialized=self.cli(name,1,'wallet-init','--wallet-dir',wallet,'--owner',public(owner))
        request={'owner':public(owner),'inputs':None,'outputs':[],'fee':'1','valid_for_blocks':8,
                 'remote':{'destination':self.regions[destination],
                           'recipient':{'owner':public(recipient),'amount':str(gross)},'destination_fee':str(destination_fee)}}
        draft=self.cli(name,1,'wallet-prepare','--wallet-dir',wallet,'--expected-wallet-head',initialized['wallet_head'],
                       '--file',self.file(f'{name}-request',request))
        key=self.file(f'{name}-owner-key',{'secret_key':(bytes([owner])*32).hex()});key.chmod(0o600)
        signed=self.cli(name,1,'wallet-sign','--wallet-dir',wallet,'--expected-wallet-head',draft['wallet_head'],
                        '--file',self.file(f'{name}-review',draft),'--review',draft['review_commitment'],'--key-file',key)
        before=self.cli(name,1,'status')['ledger']
        result=self.cli(name,1,'bft-submit','--file',self.file(f'{name}-submission',signed['commands']))
        mesh.require(result['queued'] and not result['block_included'] and self.cli(name,1,'status')['ledger']==before,
                     'queued owner submission debited native ledger')
        expected_body={'Submission':signed['commands']}
        self.wait(lambda:all(retained_body_present(Path(self.configs[k]['state'])/'state.json',expected_body)
                            for k in self.region_keys(name)),f'{name} actual signed command reaches all four validators')
        self.resume(name,before_height:=self.cli(name,1,'status')['height']+1)
        status=self.cli(name,1,'status')
        eid=draft['draft']['intent_id']
        mesh.require(eid in status['ledger']['exports'] and status['height']==before_height,'autonomous export missing')
        view=self.cli(name,1,'wallet-view','--wallet-dir',wallet,'--expected-wallet-head',signed['wallet_head'])
        mesh.require(view['reserved_owned_outputs']=='0','included export kept stale pending reservation')
        frame=self.cli(name,1,'contact-export','--export',eid)
        return {'currency':self.currency,'source':self.regions[name],'destination':self.regions[destination],
                'export':eid,'recipient':public(recipient),'net_amount':str(gross-destination_fee)},frame

    def receipt(self,name,expected):
        return self.cli(name,1,'wallet-receipt','--file',self.file(f'{name}-receipt-expectation',expected))

    def import_value(self,name,expected):
        self.wait(lambda:self.pending(name,expected['export']),f'{name} authenticated evidence pending without ledger credit')
        pending=self.receipt(name,expected)
        mesh.require(pending['state']=='VERIFIED_EVIDENCE_PENDING_IMPORT','transport alone claimed payment')
        height=self.cli(name,1,'status')['height']
        self.audit(f'{name}: proof received before local import')
        self.resume(name,height+1)
        immature=self.receipt(name,expected)
        mesh.require(immature['state']=='IMPORT_ACCEPTED_IMMATURE' and not immature['original_output_spendable_now'],
                     'autonomous import bypassed maturity')
        self.resume(name,height+3)
        receipt=self.receipt(name,expected)
        mesh.require(receipt['original_output_spendable_now'] and receipt['local_finality_covers_import'],
                     'certified imported value did not become locally spendable')
        return receipt

    def run(self):
        for name in NAMES:
            for key in self.region_keys(name):self.start(key)
        self.wait(lambda:self.reached_region('earth',3),'Earth issuance matures under autonomous local BFT')
        self.same_replicas('earth',range(4))
        self.wait(lambda:all(self.observation(k)['transport']['nodes']==12
                            and len(self.observation(k)['transport']['regions'])==3 for k in self.processes),
                  'all twelve nodes discover three regions through adjacent contacts')
        for name in ('proxima','andromeda'):
            mesh.require(self.reached_region(name,0),'paused region fabricated blocks')
            for n in range(4):
                mesh.require(self.cli(name,n,'bft-status','--signer-dir',self.signer(name,n))['records']==0,
                             'genesis pause produced a native signature')
        self.audit('three regions discovered; only Earth has issued fixture value')
        first,first_frame=self.submit_export('earth',10,'proxima',11,98,2)
        self.wait(lambda:self.pending('proxima',first['export']),'Proxima keeps first proof while every Earth process stops')
        self.offline_earth=self.cli('earth',1,'status')['ledger']
        earth_retained={n:hashlib.sha256((self.node('earth',n)/'journal.json').read_bytes()).hexdigest() for n in range(4)}
        for key in self.region_keys('earth'):self.stop(key)
        self.earth_forbidden=True
        try:
            first_receipt=self.import_value('proxima',first)
            onward,onward_frame=self.submit_export('proxima',11,'andromeda',12,93,2)
            onward_receipt=self.import_value('andromeda',onward)
            returned,return_frame=self.submit_export('andromeda',12,'earth',13,88,2)
            self.wait(lambda:any(v=='QUEUED_WAITING_CONTACT_OR_ROUTE'
                                  for v in self.observation(('andromeda',1))['transport']['messages'].values()),
                      'new return export remains queued while Earth is unreachable')
            self.audit('return deducted at Andromeda; Earth offline, no timeout refund')
            mesh.require(all(hashlib.sha256((self.node('earth',n)/'journal.json').read_bytes()).hexdigest()==earth_retained[n]
                             for n in range(4)),'offline Earth ledger changed')
        finally:self.earth_forbidden=False
        # Earth first resumes in signing pause so carriage/evidence receipt is
        # observed separately from native import and spendability.
        for key in self.region_keys('earth'):self.start(key)
        return_receipt=self.import_value('earth',returned)
        mesh.require(len({first['export'],onward['export'],returned['export']})==3,'value return reused an old export ID')
        final=self.cli('earth',1,'status')
        mesh.require(first['export'] in final['ledger']['exports'] and returned['export'] in final['ledger']['imports'],
                     'return released initial debit or lacks a new import tombstone')
        mesh.require(self.cli('earth',1,'contact-export','--export',first['export'])==first_frame,
                     'unrelated certified history changed original export carriage')
        multihop=False
        with mesh.Node(mesh.load(self.root/'mesh-config-earth-1.json',65536)) as node:
            for ident in node.summaries():
                transit=node.transit(ident)
                packet,raw,_=mesh.transit_check(transit,node.network)
                frame,_=wire.inspect_frame(raw)
                if (frame['kind']=='finalized-import' and frame['export_id']==returned['export']
                        and packet['node_id']==self.node_ids['andromeda',1] and len(transit['hops'])==2):multihop=True
        mesh.require(multihop,'returned value lacks two-hop TLS carriage through Proxima')
        observations={str(k):self.observation(k) for k in self.processes}
        for name in NAMES:
            self.same_replicas(name,range(4))
            proof=self.cli(name,1,'proof')
            local=[s for s in proof['snapshots'] if s['statement']['region']==self.regions[name]]
            mesh.require(local and all(s.get('bft') and len(s['bft']['committed']['votes'])>=3 for s in local),
                         'actual regional certificates missing')
        self.audit('complete new export/import cycle; returned value mature and initial debit retained')
        self.progress('verified: autonomous three-region value cycle')
        return {'format':'RLD-REGIONAL-BFT-MULTIREGION-GROUND-CAMPAIGN-V1',
                'fixture_only':True,'live_rld':False,'currency':self.currency,'implementation':self.implementation,
                'regions':3,'native_replicas_per_region':4,'ordinary_native_startup_used':True,
                'configured_topology':'local 0--1--2--3; adjacent gateway Earth-1--Proxima-1--Andromeda-1',
                'all_nodes_discovered_three_regions':True,'controller_generated_consensus_messages':0,
                'controller_carried_payment_proofs':0,'controller_installed_checkpoints':0,
                'remote_execution_earth_calls':0,'every_earth_node_stopped_during_onward_and_return_exports':True,
                'genesis_signing_pause_preserved_relay':True,'external_heads_retained_during_restarts':True,
                'transport_receipt_did_not_credit':True,'queued_owner_submissions_did_not_debit':True,
                'original_export_carriage_stable_after_unrelated_growth':True,
                'return_uses_new_export_and_import':True,'initial_debit_never_released':True,
                'actual_two_hop_return_carriage':True,'mesh_format':mesh.VERSION,'socket_adapter':tcp.ADAPTER,
                'TLS_1_3_and_pinned_configured_neighbors':all(o['transport']['tcp']['encrypted'] for o in observations.values()),
                'first_recipient':first_receipt,'onward_recipient':onward_receipt,'return_recipient':return_receipt,
                'replica_heights':{name:[self.cli(name,n,'status')['height'] for n in range(4)] for name in NAMES},
                'conservation_checks':self.checks,'observed_ground_phases':self.observations,
                'ground_round_timeout_seconds':60,'native_cli_calls':self.calls,'node_process_starts':self.starts,
                'same_host_same_controller':True,'independent_operators_qualified':False,
                'complete_BFT_liveness_qualified':False,'BFT_reconfiguration_implemented':False,
                'external_monotonic_custody_qualified':False,'long_disconnection_qualified':False,
                'physical_interstellar_route_qualified':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--root',type=Path,required=True,help='Fresh private fixture directory; never publish')
    parser.add_argument('--report',type=Path,required=True,help='Sanitized terminal report')
    args=parser.parse_args()
    from regional_campaign_terminal import execute
    result=execute(Campaign,args,'RLD-REGIONAL-BFT-MULTIREGION-GROUND-CAMPAIGN-V1',Path(__file__))
    print(json.dumps({'verified_three_region_cycle':result['completed'],
                      'conservation_checks':len(result['conservation_checks'])}),flush=True)


if __name__=='__main__':main()
