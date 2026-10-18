//! Optional reuse of one fully checked intrinsic block, never ledger authority.
use crate::kernel::Hash;
use std::sync::Mutex;

struct Witness {
    chain: Hash,
    raw: Vec<u8>,
}
// At most one 262144-byte block is retained per process. This is the immutable
// contact block-syntax domain of this exact executable/suite, with fixed bounds.
// Packet/frame authentication and parent-dependent execution do not use it.
static CHECKED: Mutex<Option<Witness>> = Mutex::new(None);

pub(super) fn matches(raw: &[u8], chain: Hash) -> bool {
    CHECKED.try_lock().ok().is_some_and(|entry| {
        entry
            .as_ref()
            .is_some_and(|w| w.chain == chain && w.raw == raw)
    })
}

pub(super) fn remember(raw: &[u8], chain: Hash) {
    // Only the successful complete intrinsic validator calls this function.
    // An unavailable lock/allocation simply disables this optional optimization.
    if !(270..=262144).contains(&raw.len()) {
        return;
    }
    let mut retained = Vec::new();
    if retained.try_reserve_exact(raw.len()).is_err() {
        return;
    }
    retained.extend_from_slice(raw);
    if let Ok(mut entry) = CHECKED.try_lock() {
        *entry = Some(Witness {
            chain,
            raw: retained,
        });
    }
}
