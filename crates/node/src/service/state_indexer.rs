//! Derived disk publication is independent from native commit/signing. Failure
//! preserves the complete native journal and falls back to ordinary execution.
use super::*;

pub(super) async fn worker(shared: SharedState) {
    let mut cursor = 0u64;
    let mut turn = 0u64;
    loop {
        let handle = shared.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<u64> {
            let (view, index, closed) = {
                let s = handle
                    .lock()
                    .map_err(|_| anyhow::anyhow!("node unavailable"))?;
                let view = s.node.core.proof_context();
                let Some(index) = view.state_index.clone() else {
                    return Ok(cursor);
                };
                let closed: BTreeSet<_> = s
                    .node
                    .core
                    .terminals
                    .iter()
                    .filter_map(|r| match &r.payload {
                        rld_protocol::consensus::Payload::Export(r) => {
                            Some(r.creation.controller.id)
                        }
                        rld_protocol::consensus::Payload::Cancel(c) => Some(c.controller),
                        _ => None,
                    })
                    .collect();
                (view, index, closed)
            };
            let mut targets = BTreeSet::new();
            for birth in view.state.births.records() {
                let birth = birth?;
                if !closed.contains(&birth.controller) {
                    targets.insert(birth.sequence);
                }
            }
            if view.state.sequence > 0 {
                targets.insert(view.state.sequence);
            }
            if let Some(sequence) = view.proofs.last_sequence() {
                targets.insert(sequence);
            }
            if let Err(error) = index.writable() {
                index.note(&error);
                return Ok(cursor);
            }
            let latest = view.state.sequence;
            let mut ordered: Vec<_> = targets
                .range((
                    std::ops::Bound::Excluded(cursor),
                    std::ops::Bound::Unbounded,
                ))
                .copied()
                .chain(targets.range(..=cursor).copied())
                .take(64)
                .collect();
            if turn % 2 == 0 && latest > 0 {
                ordered.retain(|n| *n != latest);
                ordered.insert(0, latest);
                ordered.truncate(64);
            }
            // The complete inventory/cursors remain local scheduling hints.
            // At most one state is built per tick; native publication never waits.
            targets.clear();
            let mut last = cursor;
            for sequence in ordered {
                last = sequence;
                let record = view
                    .history
                    .at(sequence)?
                    .context("snapshot native checkpoint")?;
                let header = &record.header;
                match index.contains(header) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => {
                        index.note(&error);
                        continue;
                    }
                }
                let result = view
                    .state_at(sequence)
                    .and_then(|state| index.publish(&state, header));
                if let Err(error) = result {
                    index.note(&error);
                }
                break;
            }
            Ok(last)
        })
        .await;
        match result {
            Ok(Ok(next)) => cursor = next,
            Ok(Err(error)) => {
                if let Ok(mut s) = shared.lock() {
                    s.node.last_error = Some(format!("state indexing: {error}"));
                }
            }
            Err(error) => {
                if let Ok(mut s) = shared.lock() {
                    s.node.last_error = Some(format!("state indexing worker: {error}"));
                }
            }
        }
        turn = turn.wrapping_add(1);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
