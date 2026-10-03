//! Fresh Earth genesis rule authorization. No predecessor commits are accepted.
//! The genesis validator set signs these exact rules and source bytes.
use super::*;
use rld_core::m0_candidate_replay::M0CandidateReplay;

pub const FORMAT: &str = "RLD-EARTH-POW-RULE-ADOPTION";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionStatement {
    pub format: String,
    pub manifest_pin: Hash,
    pub network_domain: String,
    pub zone_id: String,
    pub currency_genesis: Hash,
    #[serde(with = "decimal")]
    pub legacy_height: u128,
    pub legacy_state_root: Hash,
    pub legacy_history_sha256: Hash,
    pub rules_sha256: Hash,
    pub implementation_source_sha256: Hash,
    pub started_at: u64,
    pub initial_target: Work,
    pub old_service_reserves_reassigned: Amount,
    pub personal_allocation: Amount,
    pub incompatible_with_m0_constitution: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub public_key: String,
    pub signature: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Adoption {
    pub statement: AdoptionStatement,
    pub approvals: Vec<Approval>,
}

pub fn rules_hash() -> Hash {
    hash(include_bytes!("../../../docs/spec/EARTH-GENESIS-POW.md"))
}
impl AdoptionStatement {
    pub fn signing_bytes(&self) -> Result<Vec<u8>> {
        // Typed declaration JSON has fixed field order; integers are represented
        // exactly. The byte-domain is disjoint from every original M0 signature.
        let mut bytes = b"RLD-EARTH-POW-RULE-ADOPTION\0".to_vec();
        bytes.extend(serde_json::to_vec(self).map_err(|e| e.to_string())?);
        Ok(bytes)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(hash(&self.signing_bytes()?))
    }
}
impl Adoption {
    pub fn verify(
        &self,
        genesis: &[u8],
        history: &[u8],
        pinned_manifest: Hash,
        pinned_adoption: Hash,
    ) -> Result<Context> {
        let local_source =
            Hash::from_hex(rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT)
                .map_err(|e| e.to_string())?;
        self.verify_with_pinned_release_source(
            genesis,
            history,
            pinned_manifest,
            pinned_adoption,
            local_source,
        )
    }

    /// Verify a past adoption for a separately versioned wallet/observer.
    /// The caller must independently pin the adopted release source digest;
    /// this does not qualify the caller's new build as an adopted node binary.
    /// Consensus activation must continue using the strict `verify` method.
    pub fn verify_with_pinned_release_source(
        &self,
        genesis: &[u8],
        history: &[u8],
        pinned_manifest: Hash,
        pinned_adoption: Hash,
        pinned_release_source: Hash,
    ) -> Result<Context> {
        check(
            genesis.len() <= 65536 && history.len() <= 32 * 1024 * 1024,
            "transition input resource bound",
        )?;
        let s = &self.statement;
        check(
            s.format == FORMAT && s.manifest_pin == pinned_manifest && s.id()? == pinned_adoption,
            "transition identity or local consent mismatch",
        )?;
        check(
            s.rules_sha256 == rules_hash(),
            "unsupported PoW rule specification",
        )?;
        check(
            !pinned_release_source.is_zero()
                && s.implementation_source_sha256 == pinned_release_source,
            "transition does not bind the pinned release source",
        )?;
        check(
            s.incompatible_with_m0_constitution,
            "incompatible rule adoption must be explicit",
        )?;
        check(
            s.personal_allocation == Amount::ZERO
                && s.old_service_reserves_reassigned == Amount::TOTAL_SUPPLY,
            "transition cannot give a wallet coins or change supply",
        )?;
        check(
            history == b"[]" && s.legacy_height == 0 && hash(history) == s.legacy_history_sha256,
            "Earth genesis must have empty prior history",
        )?;
        let replay = M0CandidateReplay::from_pinned_genesis(genesis, &pinned_manifest.to_hex())?;
        let old = replay.ledger();
        check(
            old.height as u128 == s.legacy_height
                && old.state_root().map_err(|e| e.to_string())? == s.legacy_state_root.to_hex(),
            "final legacy checkpoint mismatch",
        )?;
        old.assert_conservation().map_err(|e| e.to_string())?;
        let d = &old.descriptor;
        check(
            d.network_domain == s.network_domain
                && d.zone_id == s.zone_id
                && d.currency_genesis_root == s.currency_genesis.to_hex(),
            "currency or region changed",
        )?;
        let mut expected = d.validator_keys.clone();
        expected.sort();
        check(
            expected.len() == 4 && expected.windows(2).all(|v| v[0] < v[1]),
            "unexpected predecessor committee",
        )?;
        check(
            self.approvals.len() == expected.len(),
            "all predecessor validators must explicitly adopt the incompatible rules",
        )?;
        let bytes = s.signing_bytes()?;
        for (approval, key) in self.approvals.iter().zip(&expected) {
            check(
                &approval.public_key == key,
                "approvals must exactly match sorted predecessor keys",
            )?;
            verify_bytes(key, &bytes, &approval.signature)?;
        }
        let context = Context {
            network_domain: s.network_domain.clone(),
            zone_id: s.zone_id.clone(),
            currency_genesis: s.currency_genesis,
            manifest_pin: pinned_manifest,
            transition_id: pinned_adoption,
            legacy_height: s.legacy_height,
            legacy_state_root: s.legacy_state_root,
            started_at: s.started_at,
            initial_target: s.initial_target,
        };
        context.validate()?;
        Ok(context)
    }
}

/// Prepare an unsigned, reviewable adoption from actual authenticated history.
/// This cannot activate a node or replace the required unanimous signatures.
pub fn draft(
    genesis: &[u8],
    history: &[u8],
    pin: Hash,
    initial_target: Work,
    started_at: u64,
) -> Result<AdoptionStatement> {
    check(
        history == b"[]",
        "Earth genesis must have empty prior history",
    )?;
    let replay = M0CandidateReplay::from_pinned_genesis(genesis, &pin.to_hex())?;
    let old = replay.ledger();
    old.assert_conservation().map_err(|e| e.to_string())?;
    let d = &old.descriptor;
    let s = AdoptionStatement {
        format: FORMAT.into(),
        manifest_pin: pin,
        network_domain: d.network_domain.clone(),
        zone_id: d.zone_id.clone(),
        currency_genesis: Hash::from_hex(&d.currency_genesis_root).map_err(|e| e.to_string())?,
        legacy_height: old.height as u128,
        legacy_state_root: Hash::from_hex(&old.state_root().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?,
        legacy_history_sha256: hash(history),
        rules_sha256: rules_hash(),
        implementation_source_sha256: Hash::from_hex(
            rld_core::implementation_source::IMPLEMENTATION_SOURCE_COMMITMENT,
        )
        .map_err(|e| e.to_string())?,
        started_at,
        initial_target,
        old_service_reserves_reassigned: Amount::TOTAL_SUPPLY,
        personal_allocation: Amount::ZERO,
        incompatible_with_m0_constitution: true,
    };
    Context {
        network_domain: s.network_domain.clone(),
        zone_id: s.zone_id.clone(),
        currency_genesis: s.currency_genesis,
        manifest_pin: pin,
        transition_id: s.id()?,
        legacy_height: s.legacy_height,
        legacy_state_root: s.legacy_state_root,
        started_at,
        initial_target,
    }
    .validate()?;
    Ok(s)
}
