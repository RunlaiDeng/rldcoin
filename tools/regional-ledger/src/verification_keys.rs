//! Optional bounded public-key material reuse; every message verifies strictly.
//! Exact canonical keys enter only after the unchanged Core admission checks.
//! No signatures, trust/admission decisions, epochs or ledger state are retained.
use ed25519_dalek::{Signature, VerifyingKey};
use std::{collections::VecDeque, sync::Mutex};

pub(crate) mod history_inputs;
const MAX_KEYS: usize = 64;
struct Entry {
    canonical: String,
    key: VerifyingKey,
}
#[derive(Default)]
struct Keys {
    entries: VecDeque<Entry>,
}
static KEYS: Mutex<Keys> = Mutex::new(Keys {
    entries: VecDeque::new(),
});
impl Keys {
    fn lookup(&mut self, canonical: &str) -> Option<VerifyingKey> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.canonical == canonical)?;
        let entry = self.entries.remove(index)?;
        let key = entry.key;
        self.entries.push_back(entry);
        Some(key)
    }
    fn retain(&mut self, canonical: &str, key: VerifyingKey) {
        if self.lookup(canonical).is_some() {
            return;
        }
        if self.entries.len() == MAX_KEYS {
            self.entries.pop_front();
        }
        self.entries.push_back(Entry {
            canonical: canonical.into(),
            key,
        });
    }
}
fn validated_material(canonical: &str, keys: &Mutex<Keys>) -> Result<VerifyingKey, String> {
    #[cfg(test)]
    cost::request();
    if let Ok(mut keys) = keys.lock() {
        if let Some(key) = keys.lookup(canonical) {
            #[cfg(test)]
            cost::hit();
            return Ok(key);
        }
    }
    // In particular, uppercase, reduced encodings, weak and mixed-order points
    // cannot hit an exact canonical entry or initialize material retention.
    #[cfg(test)]
    cost::validate();
    #[cfg(test)]
    let at = std::time::Instant::now();
    let checked = rld_core::validate_ed25519_public_key(canonical);
    #[cfg(test)]
    crate::bft::sign_cost::note_original_key_admission(at.elapsed().as_nanos());
    checked?;
    let public: [u8; 32] = hex::decode(canonical)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes".to_string())?;
    let key = VerifyingKey::from_bytes(&public).map_err(|error| error.to_string())?;
    // Poisoning removes acceleration: full admission and strict verification
    // still run. The lock is never held over curve work or message verification.
    if let Ok(mut keys) = keys.lock() {
        keys.retain(canonical, key);
    }
    Ok(key)
}
fn verify_using(
    keys: &Mutex<Keys>,
    public: &str,
    bytes: &[u8],
    signature: &str,
) -> Result<(), String> {
    let key = validated_material(public, keys)?;
    let raw: [u8; 64] = hex::decode(signature)
        .map_err(|error| error.to_string())?
        .try_into()
        .map_err(|_| "expected 64 bytes".to_string())?;
    if history_inputs::already_verified(public, bytes, signature) {
        #[cfg(test)]
        cost::history_reuse();
        return Ok(());
    }
    #[cfg(test)]
    cost::strict();
    let result = key
        .verify_strict(bytes, &Signature::from_bytes(&raw))
        .map_err(|error| error.to_string());
    if result.is_ok() {
        history_inputs::remember(public, bytes, signature);
    }
    #[cfg(test)]
    if result.is_ok() {
        crate::bft::sign_cost::note_original_strict_proof(public, bytes, signature);
    }
    result
}
pub(crate) fn validate_ed25519_public_key(public: &str) -> Result<(), String> {
    #[cfg(test)]
    cost::admission();
    validated_material(public, &KEYS).map(|_| ())
}
pub(crate) fn verify_bytes(public: &str, bytes: &[u8], signature: &str) -> Result<(), String> {
    verify_using(&KEYS, public, bytes, signature)
}

#[cfg(test)]
pub(crate) mod cost {
    use std::cell::RefCell;
    #[derive(Default)]
    pub(crate) struct Cost {
        pub material_hits: usize,
        pub material_requests: usize,
        pub key_admission_requests: usize,
        pub material_validations: usize,
        pub strict_attempts: usize,
        pub native_history_reused: usize,
    }
    thread_local! {
        static COST: RefCell<Cost> = const { RefCell::new(Cost {
            material_hits: 0, material_requests: 0, key_admission_requests: 0, material_validations: 0, strict_attempts: 0, native_history_reused: 0,
        }) };
    }
    pub(super) fn request() {
        COST.with(|cost| cost.borrow_mut().material_requests += 1);
    }
    pub(super) fn admission() {
        COST.with(|cost| cost.borrow_mut().key_admission_requests += 1);
    }
    pub(super) fn hit() {
        COST.with(|cost| cost.borrow_mut().material_hits += 1);
    }
    pub(super) fn validate() {
        COST.with(|cost| cost.borrow_mut().material_validations += 1);
    }
    pub(super) fn history_reuse() {
        COST.with(|cost| cost.borrow_mut().native_history_reused += 1);
    }
    pub(super) fn strict() {
        COST.with(|cost| cost.borrow_mut().strict_attempts += 1);
    }
    pub(crate) fn take() -> Cost {
        COST.with(|cost| std::mem::take(&mut *cost.borrow_mut()))
    }
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
    #[test]
    fn warm_material_never_reuses_message_success_and_matches_core() {
        let keys = Mutex::new(Keys::default());
        let (public, signature) = pair(91, b"original");
        let (_, different_signature) = pair(92, b"original");
        for _ in 0..2 {
            for (message, proof) in [
                (b"original".as_slice(), signature.as_str()),
                (b"changed".as_slice(), signature.as_str()),
                (b"original".as_slice(), different_signature.as_str()),
                (b"original".as_slice(), "00"),
                (b"original".as_slice(), "zz"),
            ] {
                assert_eq!(
                    verify_using(&keys, &public, message, proof),
                    rld_core::verify_bytes(&public, message, proof)
                );
            }
        }
        assert_eq!(keys.lock().unwrap().entries.len(), 1);
    }
    #[test]
    fn invalid_key_encodings_never_enter_retention_and_match_core() {
        let keys = Mutex::new(Keys::default());
        let (public, signature) = pair(93, b"original");
        verify_using(&keys, &public, b"original", &signature).unwrap();
        let invalid = [
            public.to_uppercase(),
            "00".repeat(32),
            format!("01{}", "00".repeat(31)),
            format!("ed{}7f", "ff".repeat(30)),
            "ff".repeat(32),
            "zz".repeat(32),
            "00".into(),
        ];
        for input in invalid {
            let original = rld_core::verify_bytes(&input, b"original", &signature);
            assert!(original.is_err());
            assert_eq!(
                verify_using(&keys, &input, b"original", &signature),
                original
            );
            assert_eq!(keys.lock().unwrap().entries.len(), 1);
        }
    }
    #[test]
    fn bounded_shared_material_eviction_preserves_strict_results() {
        let keys = Mutex::new(Keys::default());
        for seed in 1..=MAX_KEYS as u8 + 1 {
            let (public, signature) = pair(seed, b"original");
            assert_eq!(
                verify_using(&keys, &public, b"original", &signature),
                rld_core::verify_bytes(&public, b"original", &signature)
            );
            assert!(keys.lock().unwrap().entries.len() <= MAX_KEYS);
        }
        let (public, signature) = pair(1, b"original");
        assert!(keys.lock().unwrap().lookup(&public).is_none());
        assert_eq!(
            verify_using(&keys, &public, b"original", &signature),
            rld_core::verify_bytes(&public, b"original", &signature)
        );
        assert_eq!(
            verify_using(&keys, &public, b"changed", &signature),
            rld_core::verify_bytes(&public, b"changed", &signature)
        );
        assert_eq!(keys.lock().unwrap().entries.len(), MAX_KEYS);
    }
    #[test]
    fn poisoned_material_mutex_falls_back_to_full_core_checks() {
        let keys = Mutex::new(Keys::default());
        let _ = std::panic::catch_unwind(|| {
            let _guard = keys.lock().unwrap();
            panic!("fresh no-value material witness poison");
        });
        let (public, signature) = pair(94, b"original");
        for message in [b"original".as_slice(), b"changed".as_slice()] {
            assert_eq!(
                verify_using(&keys, &public, message, &signature),
                rld_core::verify_bytes(&public, message, &signature)
            );
        }
        assert!(keys.lock().err().unwrap().into_inner().entries.is_empty());
    }
    #[test]
    fn admission_material_matches_core_after_warm_signature_eviction_and_poison() {
        let keys = Mutex::new(Keys::default());
        let (public, signature) = pair(95, b"original");
        verify_using(&keys, &public, b"original", &signature).unwrap();
        for _ in 0..2 {
            for value in [
                public.clone(),
                public.to_uppercase(),
                "00".repeat(32),
                format!("01{}", "00".repeat(31)),
                format!("ed{}7f", "ff".repeat(30)),
                "ff".repeat(32),
                "zz".repeat(32),
                "00".into(),
                "9599999999999999999999999999999999999999999999999999999999999999".into(),
            ] {
                assert_eq!(
                    validated_material(&value, &keys).map(|_| ()),
                    rld_core::validate_ed25519_public_key(&value)
                );
                assert_eq!(keys.lock().unwrap().entries.len(), 1);
            }
        }
        assert!(rld_core::validate_ed25519_public_key(
            "9599999999999999999999999999999999999999999999999999999999999999"
        )
        .unwrap_err()
        .contains("prime-order subgroup"));
        for seed in 1..=MAX_KEYS as u8 + 1 {
            let (candidate, _) = pair(seed, b"original");
            assert_eq!(
                validated_material(&candidate, &keys).map(|_| ()),
                rld_core::validate_ed25519_public_key(&candidate)
            );
            assert!(keys.lock().unwrap().entries.len() <= MAX_KEYS);
        }
        assert!(keys.lock().unwrap().lookup(&public).is_none());
        assert_eq!(
            validated_material(&public, &keys).map(|_| ()),
            rld_core::validate_ed25519_public_key(&public)
        );
        assert_eq!(
            verify_using(&keys, &public, b"changed", &signature),
            rld_core::verify_bytes(&public, b"changed", &signature)
        );
        let _ = std::panic::catch_unwind(|| {
            let _guard = keys.lock().unwrap();
            panic!("fresh public material mutex poison");
        });
        for value in [
            public,
            "9599999999999999999999999999999999999999999999999999999999999999".into(),
            "zz".into(),
        ] {
            assert_eq!(
                validated_material(&value, &keys).map(|_| ()),
                rld_core::validate_ed25519_public_key(&value)
            );
        }
        assert!(keys.is_poisoned());
    }
}
