"""Preserve terminal stage and owned-process cleanup outcomes for ground runs."""
import hashlib
from pathlib import Path

import interstellar_mesh as mesh


def execute(campaign_type, args, report_format, source):
    report=Path(args.report)
    mesh.require(not report.exists() and not report.is_symlink(),'terminal report already exists; preserve it')
    campaign=campaign_type.__new__(campaign_type)
    result={};primary=None;cleanup=None
    def reason(error):
        text=f'{type(error).__name__}: {error}'
        for root in (str(args.root),str(Path(args.root).resolve())):
            text=text.replace(root,'<private-fixture>')
        return text[:4096]
    try:
        campaign.__init__(args.binary,args.root)
        returned=campaign.run()
        mesh.require(type(returned) is dict and type(returned.get('completed',True)) is bool,
                     'campaign returned an invalid terminal result')
        result=returned
    except BaseException as error:
        primary=error
        result=dict(format=report_format,completed=False,fixture_only=True,live_rld=False,failure=reason(error))
        for attribute,field in [('currency','currency'),('implementation','implementation'),
                                ('observations','observed_ground_phases'),('checks','conservation_checks'),
                                ('starts','node_process_starts')]:
            if hasattr(campaign,attribute):result[field]=getattr(campaign,attribute)
    finally:
        owned=None;clean=None
        if hasattr(campaign,'processes'):
            try:campaign.cleanup()
            except BaseException as error:cleanup=error
            owned=not campaign.processes
            clean=cleanup is None and not getattr(campaign,'_unclean_shutdown',False)
            if cleanup is None and not clean:
                cleanup=ValueError('an earlier owned process shutdown was unclean')
        if primary is None and cleanup is None and (owned is not True or clean is not True):
            cleanup=ValueError('owned process cleanup is unverified')
        result.update(completed=primary is None and cleanup is None and result.get('completed',True) is True,
                      owned_process_cleanup_verified=owned,owned_process_shutdown_clean=clean,
                      private_state_retained=Path(args.root).exists(),private_state_published=False,
                      campaign_source_sha256=hashlib.sha256(Path(source).read_bytes()).hexdigest(),
                      terminal_helper_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
        if hasattr(campaign,'inspection_anchors_sha256'):
            result['mesh_inspection_anchors_sha256']=campaign.inspection_anchors_sha256
        if primary is None:result.setdefault('failure',None)
        if cleanup is not None:
            result['cleanup_failure']=reason(cleanup)
            if primary is None:result['failure']=result['cleanup_failure']
        report.parent.mkdir(parents=True,exist_ok=True)
        mesh.atomic(report,result)
    if primary is not None:raise primary
    if cleanup is not None:raise cleanup
    return result
