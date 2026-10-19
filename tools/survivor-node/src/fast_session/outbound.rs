//! Automatic data carriage of actual native custody and existing signatures.
//! Queued/acknowledged bytes are never recipient native acceptance or value.
use super::*;
use crate::fast_peer::{codec, Network};
use std::collections::BTreeSet;
#[derive(Default)]
struct Coverage {
    through: u64,
    future: BTreeMap<u64, u64>,
    operations: BTreeSet<Hash>,
    received_bytes: BTreeSet<Hash>,
    pending_since: Option<u64>,
}
impl Coverage {
    fn cover(&mut self, first: u64, last: u64) -> Result<()> {
        ensure(first > 0 && first <= last, "INVALID outgoing native range")?;
        self.future
            .entry(first)
            .and_modify(|end| *end = (*end).max(last))
            .or_insert(last);
        while let Some((&first, &last)) = self.future.first_key_value() {
            if first > self.through + 1 {
                break;
            }
            self.through = self.through.max(last);
            self.future.remove(&first);
        }
        ensure(
            self.future.len() <= 2048,
            "RESOURCE_WAIT outgoing coverage intervals",
        )
    }
}
#[derive(Default)]
pub struct Outbound {
    binding: Option<(Hash, Hash, Hash)>,
    peers: BTreeMap<Hash, Coverage>,
    turn: usize,
    observed_packets: usize,
    last: Option<Value>,
    diagnostic: Option<String>,
}
impl Outbound {
    /// One admitted neighbor and one data class per tick. Only exact native
    /// source bytes and existing pool signatures can enter automatic carriage.
    pub fn tick(&mut self, s: &mut Session, n: &mut Network, now: u64) -> Result<()> {
        let result = self.step(s, n, now);
        match &result {
            Ok(v) => {
                self.last = Some(v.clone());
                self.diagnostic = None;
            }
            Err(e) => self.diagnostic = Some(e.clone()),
        }
        result.map(|_| ())
    }
    fn step(&mut self, s: &mut Session, n: &mut Network, now: u64) -> Result<Value> {
        s.status(s.head(), now)?;
        ensure(
            s.controlled() && n.status()["head_control"] == "TRUSTED_FILE",
            "INVALID automatic carriage trusted control",
        )?;
        n.check_custody()?;
        let (chain, identity) = n.local_scope();
        ensure(chain == s.chain, "INVALID automatic carriage currency")?;
        let binding = (chain, s.caller.binding(), identity);
        if let Some(old) = self.binding {
            ensure(old == binding, "INVALID automatic carriage runtime binding")?;
        } else {
            self.peers = n
                .admitted_ids()
                .into_iter()
                .map(|id| (id, Coverage::default()))
                .collect();
            self.binding = Some(binding);
        }
        let native = s
            .native
            .as_mut()
            .ok_or("RESOURCE_WAIT automatic carriage native restart")?;
        self.observed_packets = n.visit_packets_after(self.observed_packets, |p, received| {
            let peer = if received { p.sender } else { p.destination };
            let c = self
                .peers
                .get_mut(&peer)
                .ok_or("INVALID unadmitted carriage neighbor")?;
            match p.kind {
                1 => {
                    if received {
                        c.received_bytes.insert(hash("CARRIAGE-BYTES", &p.payload));
                    } else if let Some(index) = native.carriage_ordinal(&p.payload)? {
                        c.cover(index, index)?;
                    }
                }
                9 => {
                    let (first, blocks) = codec::decode_block_batch(&p.payload, chain)?;
                    if received {
                        for raw in blocks {
                            c.received_bytes.insert(hash("CARRIAGE-BYTES", raw));
                        }
                    } else if native.carriage_span(first, &blocks)? {
                        c.cover(first, first + blocks.len() as u64 - 1)?;
                    }
                }
                6 => {
                    let raw = codec::operation(&p.payload, chain)?;
                    c.operations.insert(fast::operation_id(raw));
                }
                _ => {}
            }
            Ok(())
        })?;
        ensure(
            self.peers
                .values()
                .map(|c| c.received_bytes.len())
                .sum::<usize>()
                <= 2048 * 32,
            "RESOURCE_WAIT retained neighbor byte witnesses",
        )?;
        if self.peers.is_empty() {
            return Ok(json!({"state":"NO_ADMITTED_NEIGHBOR"}));
        }
        let phase = self.turn % (2 * self.peers.len());
        self.turn = (phase + 1) % (2 * self.peers.len());
        let destination = *self.peers.keys().nth(phase / 2).unwrap();
        let coverage = self.peers.get_mut(&destination).unwrap();
        if phase.is_multiple_of(2) {
            for (id, raw) in s.carriage_pool()? {
                if !coverage.operations.contains(&id) {
                    let packet =
                        n.queue(destination, 6, &codec::operation_payload(chain, &raw)?, now)?;
                    coverage.operations.insert(id);
                    return Ok(
                        json!({"state":"OPERATION_QUEUED","destination":Id(destination),"operation":Id(id),"packet":Id(packet),"ledger_acceptance_known":false}),
                    );
                }
            }
            return Ok(json!({"state":"NO_UNCARRIED_SIGNATURE","destination":Id(destination)}));
        }
        let Some(group) = s
            .native
            .as_mut()
            .unwrap()
            .carriage_after(coverage.through)?
        else {
            coverage.pending_since = None;
            return Ok(
                json!({"state":"NATIVE_DATA_COVERED","destination":Id(destination),"source_records_through":coverage.through.to_string(),"ledger_acceptance_known":false}),
            );
        };
        let known = group
            .blocks
            .iter()
            .take_while(|raw| {
                coverage
                    .received_bytes
                    .contains(&hash("CARRIAGE-BYTES", raw))
            })
            .count();
        if known > 0 {
            coverage.cover(group.first, group.first + known as u64 - 1)?;
            coverage.pending_since = None;
            return Ok(
                json!({"state":"NEIGHBOR_BYTES_KNOWN","destination":Id(destination),"source_records_through":coverage.through.to_string(),"ledger_acceptance_known":false}),
            );
        }
        let since = *coverage.pending_since.get_or_insert(now);
        ensure(
            now >= since,
            "CLOCK_WAIT automatic carriage pending observation",
        )?;
        let urgent = group.blocks.iter().any(|b| b[268..270] != [0, 0]);
        if !group.closed && !urgent && now - since < 1 {
            return Ok(
                json!({"state":"BATCH_PENDING","destination":Id(destination),"local_pending_since":since.to_string()}),
            );
        }
        let large =
            group.blocks.len() == 1 && codec::BATCH_HEADER + 4 + group.blocks[0].len() > 262144;
        let (kind, payload) = if large {
            (1, group.blocks[0].clone())
        } else {
            (9, codec::block_batch(chain, group.first, &group.blocks)?)
        };
        let packet = n.queue(destination, kind, &payload, now)?;
        let last = group.first + group.blocks.len() as u64 - 1;
        coverage.cover(group.first, last)?;
        coverage.pending_since = None;
        Ok(
            json!({"state":"NATIVE_BYTES_QUEUED","destination":Id(destination),"packet":Id(packet),"first_source_record":group.first.to_string(),"last_source_record":last.to_string(),"complete_blocks":group.blocks.len(),"ledger_acceptance_known":false}),
        )
    }
    pub fn status(&self) -> Value {
        json!({"enabled":true,"scope":"EXISTING_SIGNATURES_AND_NATIVE_CUSTODY","diagnostic":self.diagnostic,"last_observation":self.last,
            "neighbors":self.peers.iter().map(|(id,c)|json!({"identity":Id(*id),"source_records_covered_through":c.through.to_string(),"retained_holes":c.future.len(),"known_neighbor_native_bytes":c.received_bytes.len(),"signed_operation_data_covered":c.operations.len(),"pending_since":c.pending_since.map(|n|n.to_string())})).collect::<Vec<_>>(),
            "owner_approval":false,"key_loading":false,"recipient_ledger_acceptance_known":false,"fast_completion_authorized":false})
    }
}
