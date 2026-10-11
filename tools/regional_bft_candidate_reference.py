"""Independent pre-migration Python selection algorithm; tests only.

Calls ordinary Native value checking; no production Runtime imports this module.
"""
import interstellar_mesh as mesh
from regional_bft_joint_epoch import signed_body


def candidate_reference(self, context, high=None):
    if high is not None:
        for _,body,message_value,_ in self.state['messages'].bodies():
            p=signed_body(body).get('Proposal')
            if p and message_value==high and p['snapshot']['statement']['height']==context['parent_height']+1:
                return p['snapshot']
        raise ValueError('highest prepared value retained without its proposal; wait for carriage')
    from regional_submission_delivery_trace import candidate_event
    candidate_event(self,'candidate_selection_started',context)
    commands=[]
    incoming=[]
    if self.joint is not None:
        plan=self.joint.plan_command(context)
        if plan is not None:incoming.append(plan)
    for retained_id,body,_,_ in self.state['messages'].bodies():
        if 'Submission' in body:candidate_event(self,'candidate_submission_seen',context,ident=retained_id)
        incoming.extend(body.get('Submission',body.get('EpochSubmission',{}).get('commands',[])))
    incoming.extend(self.native.call('bft-pending-imports'))
    seen=set()
    for command in incoming:
        ident=mesh.digest(command)
        if ident in seen or len(commands)>=4:
            continue
        seen.add(ident)
        candidate_event(self,'candidate_command_attempted',context,command=command)
        try:
            self.with_json('bft-candidate',commands+[command],'--miner',self.miner)
        except ValueError as error:
            candidate_event(self,'candidate_command_refused',context,command=command)
            # A contended native trial never established command invalidity.
            # Abort this selection; the next ordinary tick retries from the
            # native head, with no empty/partial fallback or signing here.
            from regional_contact_node import NativeRefusal
            if (isinstance(error, NativeRefusal)
                    and error.command == 'bft-candidate'
                    and type(error.exit_code) is int and error.exit_code == 1
                    and error.diagnostic.strip() in (
                        'regional candidate rejected: lock acquisition failed because the operation would block',
                        'regional candidate rejected: complete stream already locked',
                    )):
                raise
            continue  # retain stale/invalid submission; never rewrite or cancel it.
        commands.append(command)
        candidate_event(self,'candidate_command_selected',context,command=command)
    return self.with_json('bft-candidate',commands,'--miner',self.miner)
