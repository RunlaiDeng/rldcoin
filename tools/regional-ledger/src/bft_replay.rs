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
pub(super) struct PagedReplay<'a> {
    journal: &'a Journal,
    node: &'a Store,
    history: crate::storage::PagedSigningHistory<'a>,
    owner: crate::wallet_agent::Binding,
    state: State,
    head: Hash,
    count: u64,
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
        })
    }
    pub(super) fn push(&mut self, record: &Record) -> Result<()> {
        require(
            record.previous_head == self.head && record.message.approval().key == self.owner.owner,
            "paged BFT complete predecessor/key mismatch",
        )?;
        let (trust, evidence, chain) = self.history.at(record.observation.pin.height)?;
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
        let mut expected =
            self.state
                .apply_authenticated(&record.request, &self.owner.owner, trust, evidence)?;
        expected.set_approval(record.message.approval().clone());
        require(
            expected == record.message,
            "paged BFT response differs from original deterministic request/lock",
        )?;
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
        Ok(())
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
