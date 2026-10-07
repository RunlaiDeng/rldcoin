//! Exact successful cryptographic inputs inside one signer replay only.
//! No ledger, quorum, membership, epoch or context decision is retained.
use super::*;
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    rc::Rc,
};
const MAX_ENTRIES: usize = 64;
const MAX_BYTES: usize = 1024 * 1024;
struct Input {
    public: String,
    message: Vec<u8>,
    signature: String,
}
impl Input {
    fn size(&self) -> usize {
        self.public.len() + self.message.len() + self.signature.len()
    }
}
struct Witness {
    marker: Rc<Cell<bool>>,
    entries: VecDeque<Input>,
    bytes: usize,
}
thread_local! {
    static INPUTS: RefCell<Option<Witness>> = const { RefCell::new(None) };
}
/// Owned by one PagedReplay. It cannot move to a different thread or load from
/// disk. Nested invocations get fresh entries and restore only their own caller.
pub(crate) struct Invocation {
    previous: Option<Witness>,
    _same_thread: PhantomData<Rc<()>>,
}
impl Invocation {
    pub(crate) fn enter() -> Self {
        let previous = INPUTS.with(|inputs| {
            inputs.replace(Some(Witness {
                marker: Rc::new(Cell::new(false)),
                entries: VecDeque::new(),
                bytes: 0,
            }))
        });
        Self {
            previous,
            _same_thread: PhantomData,
        }
    }
}
impl Drop for Invocation {
    fn drop(&mut self) {
        INPUTS.with(|inputs| {
            inputs.replace(self.previous.take());
        });
    }
}
/// Reuse is enabled only while actual Native records execute. All signer
/// request proofs and outer responses remain on the original strict path.
pub(crate) struct NativeRecord {
    previous: Option<(Rc<Cell<bool>>, bool)>,
    _same_thread: PhantomData<Rc<()>>,
}
impl NativeRecord {
    pub(crate) fn enter() -> Self {
        let previous = INPUTS.with(|inputs| {
            let inputs = inputs.try_borrow().ok()?;
            let witness = inputs.as_ref()?;
            let previous = (witness.marker.clone(), witness.marker.replace(true));
            Some(previous)
        });
        Self {
            previous,
            _same_thread: PhantomData,
        }
    }
}
impl Drop for NativeRecord {
    fn drop(&mut self) {
        if let Some((marker, native)) = &self.previous {
            // Reset the original scope even while its entries are borrowed or
            // a nested invocation currently owns the thread-local slot.
            marker.set(*native);
        }
    }
}
pub(super) fn already_verified(public: &str, message: &[u8], signature: &str) -> bool {
    INPUTS.with(|inputs| {
        let Ok(mut inputs) = inputs.try_borrow_mut() else {
            return false;
        };
        let Some(witness) = inputs.as_mut() else {
            return false;
        };
        if !witness.marker.get() {
            return false;
        }
        let Some(index) = witness.entries.iter().position(|input| {
            input.public == public && input.message == message && input.signature == signature
        }) else {
            return false;
        };
        let exact = witness
            .entries
            .remove(index)
            .expect("exact retained input position");
        witness.entries.push_back(exact);
        true
    })
}
/// Called only AFTER original strict verification succeeds. Any contention or
/// oversize input disables optional retention, never verification or execution.
pub(super) fn remember(public: &str, message: &[u8], signature: &str) {
    let Some(size) = public
        .len()
        .checked_add(message.len())
        .and_then(|n| n.checked_add(signature.len()))
    else {
        return;
    };
    if size > MAX_BYTES {
        return;
    }
    INPUTS.with(|inputs| {
        let Ok(mut inputs) = inputs.try_borrow_mut() else {
            return;
        };
        let Some(witness) = inputs.as_mut() else {
            return;
        };
        if witness.entries.iter().any(|input| {
            input.public == public && input.message == message && input.signature == signature
        }) {
            return;
        }
        while witness.entries.len() >= MAX_ENTRIES || witness.bytes + size > MAX_BYTES {
            let Some(old) = witness.entries.pop_front() else {
                return;
            };
            witness.bytes -= old.size();
        }
        witness.entries.push_back(Input {
            public: public.into(),
            message: message.into(),
            signature: signature.into(),
        });
        witness.bytes += size;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn pair(seed: u8, message: &[u8]) -> (String, String) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        (
            hex::encode(key.verifying_key().to_bytes()),
            hex::encode(key.sign(message).to_bytes()),
        )
    }
    fn verify(keys: &Mutex<Keys>, public: &str, message: &[u8], signature: &str) {
        assert_eq!(
            verify_using(keys, public, message, signature),
            rld_core::verify_bytes(public, message, signature)
        );
    }
    #[test]
    fn native_only_exact_inputs_changed_bytes_keys_signatures_and_new_invocation_match_core() {
        let keys = Mutex::new(Keys::default());
        let (public, signature) = pair(96, b"original");
        let (other, _) = pair(97, b"original");
        cost::take();
        let scope = Invocation::enter();
        verify(&keys, &public, b"original", &signature);
        verify(&keys, &public, b"original", &signature);
        assert_eq!(cost::take().strict_attempts, 2); // Outer/request paths never reuse.
        {
            let _native = NativeRecord::enter();
            verify(&keys, &public, b"original", &signature);
            assert_eq!(cost::take().native_history_reused, 1);
            for (key, message, proof) in [
                (public.as_str(), b"changed".as_slice(), signature.as_str()),
                (other.as_str(), b"original".as_slice(), signature.as_str()),
                (public.as_str(), b"original".as_slice(), "00"),
                (
                    public.as_str(),
                    b"original".as_slice(),
                    "00".repeat(64).as_str(),
                ),
            ] {
                verify(&keys, key, message, proof);
            }
            assert_eq!(cost::take().native_history_reused, 0);
            verify(&keys, &public, b"original", &signature);
            assert_eq!(cost::take().native_history_reused, 1);
        }
        verify(&keys, &public, b"original", &signature);
        assert_eq!(cost::take().strict_attempts, 1);
        drop(scope);
        assert!(INPUTS.with(|inputs| inputs.borrow().is_none()));
        let _fresh = Invocation::enter();
        let _native = NativeRecord::enter();
        verify(&keys, &public, b"original", &signature);
        let result = cost::take();
        assert_eq!(
            (result.strict_attempts, result.native_history_reused),
            (1, 0)
        );
    }
    #[test]
    fn bounded_eviction_nested_scopes_and_unwind_preserve_independent_verification() {
        let keys = Mutex::new(Keys::default());
        let (public, signature) = pair(98, b"original");
        let outer = Invocation::enter();
        verify(&keys, &public, b"original", &signature);
        let native = NativeRecord::enter();
        let _ = std::panic::catch_unwind(|| {
            let _inner = Invocation::enter();
            let _inner_native = NativeRecord::enter();
            assert!(!already_verified(&public, b"original", &signature));
            verify(&keys, &public, b"original", &signature);
            panic!("fresh no-value exact proof scope unwind");
        });
        assert!(already_verified(&public, b"original", &signature));
        for index in 0..MAX_ENTRIES + 1 {
            let message = format!("independent-{index}");
            let (_, proof) = pair(98, message.as_bytes());
            verify(&keys, &public, message.as_bytes(), &proof);
        }
        assert!(!already_verified(&public, b"original", &signature));
        INPUTS.with(|inputs| {
            let inputs = inputs.borrow();
            let witness = inputs.as_ref().unwrap();
            assert_eq!(witness.entries.len(), MAX_ENTRIES);
            assert!(witness.bytes <= MAX_BYTES);
        });
        let oversized = vec![0; MAX_BYTES];
        let (_, proof) = pair(98, &oversized);
        verify(&keys, &public, &oversized, &proof);
        assert!(!already_verified(&public, &oversized, &proof));
        for index in 0..4 {
            let message = vec![index as u8; MAX_BYTES / 3];
            let (_, proof) = pair(98, &message);
            verify(&keys, &public, &message, &proof);
            INPUTS.with(|inputs| assert!(inputs.borrow().as_ref().unwrap().bytes <= MAX_BYTES));
        }
        drop(native);
        drop(outer);
        assert!(INPUTS.with(|inputs| inputs.borrow().is_none()));
    }
    #[test]
    fn held_input_borrow_drop_never_leaks_native_reuse_to_outer_verification() {
        let keys = Mutex::new(Keys::default());
        let (public, signature) = pair(99, b"original");
        let _scope = Invocation::enter();
        verify(&keys, &public, b"original", &signature);
        let native = NativeRecord::enter();
        assert!(already_verified(&public, b"original", &signature));
        INPUTS.with(|inputs| {
            let _held = inputs.borrow_mut();
            drop(native);
        });
        assert!(
            !already_verified(&public, b"original", &signature),
            "Native scope exit leaked reuse while retained inputs were borrowed"
        );
        cost::take();
        verify(&keys, &public, b"original", &signature);
        let result = cost::take();
        assert_eq!(
            (result.strict_attempts, result.native_history_reused),
            (1, 0)
        );
    }
}
