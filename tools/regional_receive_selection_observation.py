"""One watched-envelope scalar selection boundary, never reception authority.

No classifier, packet read, Native call or cursor update runs in this observer.
Only the caller's existing selection inputs and choices supply observations.
"""
from bisect import bisect_right


def reject(service):
    try:service.contact_trace.reject()
    except Exception:pass


def begin(service,summaries,receipts,destination,eligible,remaining,quota):
    trace=getattr(service,'contact_trace',None)
    watch=getattr(trace,'watch_envelope_id',None)
    if watch is None:return None
    try:
        matched=[i for i,t in summaries.items()
                 if t['kind']=='regional-bft' and t['export_id']==watch]
        local=[i for i in matched if summaries[i]['destination']==destination]
        watched=set(local)
        return dict(envelope_id=watch,watched_summary_count=len(matched),
                    watched_destination_count=len(local),
                    watched_receipt_count=sum(i in receipts for i in local),
                    watched_seen_count=sum(i in service.bft_seen for i in local),
                    watched_attempted_count=sum(i in quota['attempted'] for i in local) if quota is not None else 0,
                    watched_eligible_count=sum(i in watched for i in eligible),
                    eligible_count=len(eligible),remaining_count=max(0,remaining),
                    novel_count=0,background_count=0,novel_watch_rank=0,background_watch_rank=0,
                    _watched=watched)
    except Exception:reject(service);return None


def classified(service,observation,novel,background):
    if observation is None:return
    try:
        for kind,items in (('novel',novel),('background',background)):
            after=service.receive_after[kind]
            start=0 if after is None or not items else bisect_right(items,after)%len(items)
            ordered=items[start:]+items[:start]
            observation[kind+'_count']=len(items)
            observation[kind+'_watch_rank']=next((i+1 for i,p in enumerate(ordered)
                                                if p in observation['_watched']),0)
    except Exception:reject(service);observation.clear()


def finish(service,observation,selected,mode,inspected=0):
    if not observation:return
    try:
        watched=observation['_watched']
        fields={k:v for k,v in observation.items() if k!='_watched'}
        fields.update(selection_mode=mode,selected=len(selected),inspected_count=inspected,
                      watched_selected_count=sum(i in watched for i in selected))
        service.contact_trace.event('native_selection_watch',**fields)
    except Exception:reject(service)
