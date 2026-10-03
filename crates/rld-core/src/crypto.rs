use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Identity {
    pub public_key: String,
    pub secret_key: String,
}

impl Identity {
    pub fn address(&self, zone_id: &str) -> String {
        format!("rld:{zone_id}:{}", self.public_key)
    }
}

pub fn generate_identity() -> Identity {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let signing_key = SigningKey::from_bytes(&secret);
    Identity {
        public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        secret_key: hex::encode(signing_key.to_bytes()),
    }
}

pub fn sign_bytes(secret_key_hex: &str, bytes: &[u8]) -> Result<String, String> {
    let secret = decode_array::<32>(secret_key_hex)?;
    let key = SigningKey::from_bytes(&secret);
    Ok(hex::encode(key.sign(bytes).to_bytes()))
}

pub fn verify_bytes(public_key_hex: &str, bytes: &[u8], signature_hex: &str) -> Result<(), String> {
    validate_ed25519_public_key(public_key_hex)?;
    let public = decode_array::<32>(public_key_hex)?;
    let signature = decode_array::<64>(signature_hex)?;
    let key = VerifyingKey::from_bytes(&public).map_err(|error| error.to_string())?;
    let signature = Signature::from_bytes(&signature);
    key.verify_strict(bytes, &signature)
        .map_err(|error| error.to_string())
}

/// Validates canonical Ed25519 public-key material before admitting it to a
/// consensus validator set. Signature verification is still required for each
/// message; this only excludes malformed encodings and small-order keys whose
/// group structure is unsafe for validator identity.
pub fn validate_ed25519_public_key(public_key_hex: &str) -> Result<(), String> {
    let public = decode_array::<32>(public_key_hex)?;
    if hex::encode(public) != public_key_hex {
        return Err("Ed25519 public key must be canonical lowercase hex".into());
    }
    if !canonical_ed25519_y(&public) {
        return Err("Ed25519 public key uses a non-canonical compressed point".into());
    }
    let key = VerifyingKey::from_bytes(&public).map_err(|error| error.to_string())?;
    if key.is_weak() {
        return Err("Ed25519 public key has small order".into());
    }
    let point = CompressedEdwardsY(public)
        .decompress()
        .ok_or_else(|| "Ed25519 public key does not encode a curve point".to_string())?;
    if !point.is_torsion_free() {
        return Err("Ed25519 public key is outside the prime-order subgroup".into());
    }
    Ok(())
}

fn canonical_ed25519_y(public: &[u8; 32]) -> bool {
    // RFC 8032 encodes y in the low 255 bits and requires y < 2^255 - 19.
    // curve25519-dalek intentionally accepts some reduced field encodings for
    // compatibility, so validator admission performs this check explicitly.
    const FIELD_MODULUS_LE: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let mut y = *public;
    y[31] &= 0x7f;
    for index in (0..32).rev() {
        if y[index] < FIELD_MODULUS_LE[index] {
            return true;
        }
        if y[index] > FIELD_MODULUS_LE[index] {
            return false;
        }
    }
    false
}

pub fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn hash_parts(parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hex::encode(hasher.finalize())
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(value).map_err(|error| error.to_string())?;
    bytes.try_into().map_err(|_| format!("expected {N} bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_round_trip() {
        let identity = generate_identity();
        let signature = sign_bytes(&identity.secret_key, b"rld").unwrap();
        verify_bytes(&identity.public_key, b"rld", &signature).unwrap();
        assert!(verify_bytes(&identity.public_key, b"other", &signature).is_err());
        validate_ed25519_public_key(&identity.public_key).unwrap();
        assert!(validate_ed25519_public_key(&identity.public_key.to_uppercase()).is_err());
    }

    #[test]
    fn strict_verification_rejects_small_order_identity_forgery() {
        let mut identity_point = [0u8; 32];
        identity_point[0] = 1;
        let mut forged_signature = [0u8; 64];
        forged_signature[0] = 1;
        let public_key = hex::encode(identity_point);
        assert!(validate_ed25519_public_key(&public_key).is_err());
        assert!(verify_bytes(&public_key, b"forged", &hex::encode(forged_signature)).is_err());
    }

    #[test]
    fn validator_admission_rejects_reduced_noncanonical_y_encodings() {
        let mut field_modulus = [0xffu8; 32];
        field_modulus[0] = 0xed;
        field_modulus[31] = 0x7f;
        let mut found_permissively_decodable_nonweak = false;
        for increment in 0u8..19 {
            let mut candidate = field_modulus;
            candidate[0] = candidate[0].checked_add(increment).unwrap();
            if VerifyingKey::from_bytes(&candidate).is_ok_and(|key| !key.is_weak()) {
                found_permissively_decodable_nonweak = true;
                assert!(validate_ed25519_public_key(&hex::encode(candidate)).is_err());
            }
        }
        assert!(found_permissively_decodable_nonweak);
    }

    #[test]
    fn validator_admission_rejects_mixed_torsion_public_keys() {
        use curve25519_dalek::constants::{ED25519_BASEPOINT_POINT, EIGHT_TORSION};

        let mixed_order = ED25519_BASEPOINT_POINT + EIGHT_TORSION[1];
        assert!(!mixed_order.is_small_order());
        assert!(!mixed_order.is_torsion_free());
        let encoded = mixed_order.compress().to_bytes();
        let permissive = VerifyingKey::from_bytes(&encoded).unwrap();
        assert!(!permissive.is_weak());
        assert!(validate_ed25519_public_key(&hex::encode(encoded)).is_err());
    }
}
