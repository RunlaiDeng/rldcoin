//! Same complete native record replay for the ordinary Agent and read-only
//! retained pages. No persisted hashing/state witness initializes authority.
use super::*;

/// Hashes exact legacy JSON prefixes without cloning the growing record vector.
/// This process-local cursor begins at the fully serialized immutable header.
/// Its digest is byte identity only; Replay authenticates every complete record.
struct LegacyHead {
    hash: Sha256,
    bytes: usize,
    count: usize,
}
impl LegacyHead {
    fn new(journal: &Journal) -> Result<Self> {
        #[derive(Serialize)]
        struct Header<'a> {
            binding: &'a Binding,
            creation: &'a Observation,
            #[serde(skip_serializing_if = "Option::is_none")]
            origin: &'a Option<Box<crate::joint_roles::VoterOrigin>>,
            records: &'a [Record],
        }
        let raw = encode(
            "bft-signer-journal-v1",
            &Header {
                binding: &journal.binding,
                creation: &journal.creation,
                origin: &journal.origin,
                records: &[],
            },
        )?;
        require(raw.ends_with(b"[]}"), "BFT journal canonical record suffix")?;
        let mut hash = Sha256::new();
        hash.update(&raw[..raw.len() - 2]);
        Ok(Self {
            hash,
            bytes: raw.len(),
            count: 0,
        })
    }
    fn head(&self) -> Hash {
        let mut hash = self.hash.clone();
        hash.update(b"]}");
        Hash(hash.finalize().into())
    }
    fn push(&mut self, record: &Record) -> Result<()> {
        require(self.count < MAX_RECORDS, "BFT journal record capacity")?;
        let raw = serde_json::to_vec(record).map_err(|_| "BFT record encoding")?;
        let comma = usize::from(self.count > 0);
        let size = self
            .bytes
            .checked_add(raw.len())
            .and_then(|n| n.checked_add(comma))
            .ok_or("BFT journal byte overflow")?;
        require(size <= MAX_BYTES, "BFT signer byte capacity")?;
        if comma > 0 {
            self.hash.update(b",");
        }
        self.hash.update(&raw);
        self.bytes = size;
        self.count += 1;
        Ok(())
    }
}

/// State stays local until all complete records and both final heads pass.
/// Genesis/creation, historical native observations, era/custody ancestry,
/// requests, lock transitions and actual retained signatures all authenticate.
pub(super) struct Replay<'a> {
    journal: &'a Journal,
    node: &'a Store,
    owner: crate::wallet_agent::Binding,
    head: LegacyHead,
    state: State,
}
impl<'a> Replay<'a> {
    pub(super) fn new(journal: &'a Journal, node: &'a Store, depth: usize) -> Result<Self> {
        journal.validate_header(node, depth)?;
        Ok(Self {
            journal,
            node,
            owner: crate::wallet_agent::Binding {
                currency: journal.binding.currency,
                region: journal.binding.region,
                owner: journal.binding.key.clone(),
            },
            head: LegacyHead::new(journal)?,
            state: State::default(),
        })
    }
    pub(super) fn push(&mut self, record: &Record) -> Result<()> {
        let b = &self.owner;
        let node = self.node;
        require(
            record.previous_head == self.head.head() && record.message.approval().key == b.owner,
            "BFT journal predecessor/key mismatch",
        )?;
        record.observation.check(node, b)?;
        let c = record.request.context()?;
        require(
            node.trust.region(b.region)?.rules != ROLE_RULES
                || c.epoch == self.journal.creation.pin.epoch,
            "role voter cannot change era inside its original journal",
        )?;
        require(
            c.currency == b.currency
                && c.region == b.region
                && c.parent_height == record.observation.pin.height
                && c.parent_block == record.observation.pin.tip
                && c.parent_state == record.observation.pin.state
                && c.previous == record.observation.pin.finality
                && c.epoch == record.observation.pin.epoch,
            "BFT vote observation does not bind actual native parent",
        )?;
        let mut expected = self.state.apply(&record.request, &b.owner, node)?;
        expected.set_approval(record.message.approval().clone());
        require(
            expected == record.message,
            "BFT retained message differs from deterministic request/state",
        )?;
        verify_bytes(
            &b.owner,
            &record.message.bytes()?,
            &record.message.approval().signature,
        )?;
        self.head.push(record)
    }
    pub(super) fn finish(self, expected: Hash) -> Result<State> {
        require(
            self.head.head() == expected,
            "BFT complete native journal head differs",
        )?;
        Ok(self.state)
    }
}

/// New signed paged custody keeps its complete original record chain in pages.
/// Native genesis replay supplies every historical parent; no decoded cache or
/// active evidence from the final height may authorize an old request.
/// One exact nested proof already fully verified against this invocation's
/// actually executed Native prefix. It is never serialized or shared across
/// signer calls; every outer response and commit quorum still verifies.
#[derive(Default)]
pub(crate) struct ProposalProof {
    retained: Option<(Hash, Hash, Proposal, Option<Quorum>)>,
    #[cfg(test)]
    pub(crate) full_checks: usize,
    #[cfg(test)]
    pub(crate) reused_checks: usize,
}
impl ProposalProof {
    pub(crate) fn verify(
        &mut self,
        proposal: &Proposal,
        trust: &Trust,
        evidence: &VerifiedEvidence,
        executed: Hash,
    ) -> Result<Option<Quorum>> {
        if let Some((head, binding, original, selected)) = &self.retained {
            if *head == executed && *binding == trust.binding && original == proposal {
                #[cfg(test)]
                {
                    self.reused_checks += 1;
                    crate::bft::sign_cost::note_proposal_proof(false);
                }
                return Ok(selected.clone());
            }
        }
        #[cfg(test)]
        {
            self.full_checks += 1;
            crate::bft::sign_cost::note_proposal_proof(true);
        }
        let selected = proposal.verify(trust, evidence)?;
        self.retained = Some((executed, trust.binding, proposal.clone(), selected.clone()));
        Ok(selected)
    }
}
pub(super) struct PagedReplay<'a> {
    journal: &'a Journal,
    node: &'a Store,
    history: crate::storage::PagedSigningHistory<'a>,
    owner: crate::wallet_agent::Binding,
    state: State,
    head: Hash,
    count: u64,
    proposal_proof: ProposalProof,
    _signature_inputs: crate::verification_keys::history_inputs::Invocation,
    #[cfg(test)]
    proposal_probe: Option<(Hash, Hash, Proposal)>,
}
impl<'a> PagedReplay<'a> {
    pub(super) fn new(journal: &'a Journal, node: &'a Store, head: Hash) -> Result<Self> {
        require(
            journal.records.is_empty()
                && journal.origin.is_none()
                && crate::paged_bft::is_profile(&node.trust.region(journal.binding.region)?.rules)
                && journal.binding.currency == node.trust.currency()?
                && journal.binding.region == node.chain.region
                && journal.creation.pin.height == 0
                && node
                    .trust
                    .region(journal.binding.region)?
                    .validators
                    .contains(&journal.binding.key),
            "paged BFT immutable genesis signer header/profile/member",
        )?;
        validate_ed25519_public_key(&journal.binding.key)?;
        let owner = crate::wallet_agent::Binding {
            currency: journal.binding.currency,
            region: journal.binding.region,
            owner: journal.binding.key.clone(),
        };
        let signature_inputs = crate::verification_keys::history_inputs::Invocation::enter();
        let mut history = node.paged_signing_history()?;
        let (_, _, chain) = history.at(0)?;
        journal.creation.check_selected(node, &owner, chain)?;
        Ok(Self {
            journal,
            node,
            history,
            owner,
            state: State::default(),
            head,
            count: 0,
            proposal_proof: ProposalProof::default(),
            _signature_inputs: signature_inputs,
            #[cfg(test)]
            proposal_probe: None,
        })
    }
    pub(super) fn push(&mut self, record: &Record) -> Result<()> {
        #[cfg(test)]
        let mut cost = crate::bft::sign_cost::ReplayClock::new();
        require(
            record.previous_head == self.head && record.message.approval().key == self.owner.owner,
            "paged BFT complete predecessor/key mismatch",
        )?;
        let (executed, trust, evidence, chain) = self
            .history
            .at_with_executed_head(record.observation.pin.height)?;
        record
            .observation
            .check_selected(self.node, &self.owner, chain)?;
        let c = record.request.context()?;
        require(
            c.currency == self.owner.currency
                && c.region == self.owner.region
                && c.parent_height == chain.height()
                && c.parent_block == chain.tip()?
                && c.parent_state == chain.ledger.root()?
                && c.previous == chain.finalized
                && c.epoch == chain.epoch
                && c.epoch == self.journal.creation.pin.epoch,
            "paged BFT request differs from complete historical parent",
        )?;
        #[cfg(test)]
        cost.mark(0);
        let proof = &mut self.proposal_proof;
        let mut expected = self.state.apply_authenticated_with_proposal(
            &record.request,
            &self.owner.owner,
            trust,
            evidence,
            |proposal, trust, evidence| proof.verify(proposal, trust, evidence, executed),
        )?;
        #[cfg(test)]
        if let Request::Prepare(proposal) | Request::Commit { proposal, .. } = &record.request {
            let duplicate =
                self.proposal_probe
                    .as_ref()
                    .is_some_and(|(old_head, old_trust, old)| {
                        *old_head == executed
                            && *old_trust == trust.binding
                            && old == proposal.as_ref()
                    });
            crate::bft::sign_cost::note_original_proposal_check(duplicate);
            self.proposal_probe = Some((executed, trust.binding, *proposal.clone()));
        }
        expected.set_approval(record.message.approval().clone());
        require(
            expected == record.message,
            "paged BFT response differs from original deterministic request/lock",
        )?;
        #[cfg(test)]
        cost.mark(1);
        verify_bytes(
            &self.owner.owner,
            &record.message.bytes()?,
            &record.message.approval().signature,
        )?;
        self.head = crate::retained_pages::next_head(self.head, self.count, record)?;
        self.count = self
            .count
            .checked_add(1)
            .ok_or("paged signer count overflow")?;
        #[cfg(test)]
        {
            cost.mark(2);
            cost.finish();
        }
        Ok(())
    }
    /// No cursor/state survives this invocation. Native history and every old
    /// signer record have executed before a clone can review the new request.
    pub(super) fn authenticate_current(&mut self, expected: Hash) -> Result<State> {
        require(
            self.head == expected,
            "paged BFT exact complete caller head differs",
        )?;
        self.history.check_complete(self.node)?;
        Ok(self.state.clone())
    }
    pub(super) fn finish(self, expected: Hash) -> Result<State> {
        require(
            self.head == expected,
            "paged BFT exact complete caller head differs",
        )?;
        self.history.finish(self.node)?;
        Ok(self.state)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    /// Independent full serialization oracle at every prefix, including
    /// optional full rollover ancestry; the cursor never uses this oracle.
    pub(crate) fn compare_all_prefixes(journal: &Journal) {
        let mut cursor = LegacyHead::new(journal).unwrap();
        let mut complete = journal.clone();
        complete.records.clear();
        assert_eq!(cursor.head(), complete.head().unwrap());
        for record in &journal.records {
            cursor.push(record).unwrap();
            complete.records.push(record.clone());
            assert_eq!(cursor.head(), complete.head().unwrap());
        }
    }
}
