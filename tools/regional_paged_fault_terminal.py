"""Retain terminal/cleanup facts for one explicit prepared full-fault attempt.

A successful body is insufficient: every owned process and relay must actually
stop, all12cold checks must finish, and the original total deadline must hold.
Private raw evidence never becomes a public identity/key/config/custody export.
"""
from pathlib import Path
import time

import interstellar_mesh as mesh


def public_result(result):
    names=('fixture_only','live_rld','stage_seconds','round_seconds','new_height_limit',
        'absolute_height_caps','maturity','quorum','original_owner_first_signs','owner_requests_replaced',
        'custody_copied','controller_consensus_or_checkpoints','ordinary_service_starts','service_terminals',
        'native_accounting','final_heights','directed_fault_relays','unknown_process_observations',
        'independent_freshness_custody_physical_long_history_qualified','whole_goal_completed')
    public={name:result[name] for name in names if name in result}
    public['stopped_native_envelope_transport_checks']=[]
    for row in result.get('all12fixed_head_native_and_complete_envelopes',[]):
        cold=row['envelopes'];transport=row['transport']
        public['stopped_native_envelope_transport_checks'].append(dict(region=row['region'],index=row['index'],
            height=row['height'],messages_authenticated=cold['messages_authenticated'],
            full_native_authentication=cold['full_native_authentication'],
            implicit_head_adoption=cold['implicit_head_adoption'],
            retained_state_bytes=cold['retained_state_bytes'],state_limit_bytes=cold['state_limit_bytes'],
            transport_files=transport['retained_files'],transport_bytes=transport['retained_bytes'],
            all_indexed_transport_archives_authenticated=transport['all_indexed_transport_archives_authenticated'],
            separate_caller_head_verified=row['separate_caller_head_verified']))
    return public


def completed_body(result):
    return (type(result) is dict and result.get('completed') is True
        and result.get('full_fault_qualified') is True and result.get('fixture_only') is True
        and result.get('live_rld') is False and result.get('whole_goal_completed') is False
        and (result.get('stage_seconds'),result.get('round_seconds'),result.get('new_height_limit'),
             result.get('maturity'),result.get('quorum'))==(600,60,24,2,3)
        and result.get('absolute_height_caps')==dict(earth=27,proxima=24,andromeda=24)
        and result.get('original_owner_first_signs')==3 and result.get('owner_requests_replaced')==0
        and result.get('custody_copied') is False and result.get('controller_consensus_or_checkpoints')==0
        and len(result.get('all12fixed_head_native_and_complete_envelopes',[]))==12
        and {(v.get('region'),v.get('index')) for v in result['all12fixed_head_native_and_complete_envelopes']}
            =={(r,n) for r in ('earth','proxima','andromeda') for n in range(4)}
        and all(type(v.get('index')) is int and v.get('separate_caller_head_verified') is True
            and v['envelopes'].get('full_native_authentication') is True
            and v['envelopes'].get('implicit_head_adoption') is False
            and v['transport'].get('all_indexed_transport_archives_authenticated') is True
            for v in result['all12fixed_head_native_and_complete_envelopes']))


def execute(make_driver, deadline, private_report, *, now=time.monotonic):
    """The caller separately pins source/CLI/provenance and authorizes once600.

    Persist raw failure and terminal observations even after construction fails.
    Never recover, reconcile, first-sign again or open a stopped failed fixture.
    Returned public observations are sanitized and are not signing authority.
    """
    private_report=Path(private_report)
    mesh.require(not private_report.exists(),'retain existing terminal report')
    driver=None;result={};primary=None;cleanup=None;body_on_time=False
    def reason(error):
        text=f'{type(error).__name__}: {error}'
        if driver is not None:
            for value in (str(driver.root),str(driver.output)):text=text.replace(value,'<private-fixture>')
        return text[:4096]
    try:
        driver=make_driver()
        result=driver.run()
        mesh.require(completed_body(result),'full driver body lacks complete original scope')
        body_on_time=now()<=deadline
        mesh.require(body_on_time,'original600second whole body/cold deadline exceeded')
    except BaseException as error:primary=error
    finally:
        if driver is not None:
            try:driver.cleanup()
            except BaseException as error:cleanup=error
        processes_stopped=driver is not None and not driver.processes
        relay_stopped=(driver is not None and all(r.closed.is_set() and not r.thread.is_alive()
            and not any(w.is_alive() for w in r.workers) for r in driver.relays))
        complete=primary is None and cleanup is None and processes_stopped and relay_stopped and body_on_time
        private=dict(format='RLD-PAGED-FULL-FAULT-TERMINAL-PRIVATE-V1',completed=complete,
            failure=reason(primary) if primary is not None else None,
            cleanup_failure=reason(cleanup) if cleanup is not None else None,
            owned_processes_stopped=processes_stopped,owned_relays_stopped=relay_stopped,
            body_and_full_cold_within_original_deadline=body_on_time,raw_body=result,
            service_terminals=driver.terminal if driver is not None else [],
            native_calls=driver.calls if driver is not None else [],
            attempted_owner_signs=getattr(driver,'attempted_owner_signs',None),
            released_owner_responses=driver.signed_count if driver is not None else 0,
            exact_stopped_native_heads={f'{label}:{index}':head
                for (label,index),head in driver.stopped_heads.items()} if driver is not None else {},
            failed_currency_never_reopen=not complete,private_state_retained=True)
        private_report.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        mesh.atomic(private_report,private)
    # Sanitize only a fully checked successful body; a partial body cannot claim
    # native/custody qualification. The raw original remains private on disk.
    public=public_result(result) if complete else {}
    public.update(format='RLD-PAGED-FULL-FAULT-TERMINAL-V1',completed=complete,
        full_fault_qualified=complete,failure=private['failure'],cleanup_failure=private['cleanup_failure'],
        owned_processes_stopped=processes_stopped,owned_relays_stopped=relay_stopped,
        body_and_full_cold_within_original_deadline=body_on_time,
        attempted_owner_signs=private['attempted_owner_signs'],released_owner_responses=private['released_owner_responses'],
        failed_currency_never_reopen=not complete,legacy_value_strict='OPEN',whole_goal_completed=False)
    return public
