//! Bounded wire sharing only. Expanded evidence still needs complete native
//! authentication; a prefix reference is never a checkpoint or value authority.
use super::*;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prefix {
    pub checkpoint: Hash,
    pub blocks: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarriedSnapshot {
    pub prefix: Option<Prefix>,
    pub snapshot: Snapshot,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CarriedEvidence {
    pub snapshots: Vec<CarriedSnapshot>,
}
impl CarriedEvidence {
    pub fn pack(evidence: &Evidence) -> Result<Self> {
        require(
            evidence.snapshots.len() <= MAX_SNAPSHOTS,
            "carried snapshot count bound",
        )?;
        encode("evidence", evidence)?;
        let mut result = Self { snapshots: vec![] };
        let mut earlier: BTreeMap<Hash, usize> = BTreeMap::new();
        for (index, snapshot) in evidence.snapshots.iter().enumerate() {
            require(snapshot.blocks.len() <= MAX_BLOCKS, "carried block bound")?;
            let base = snapshot.statement.previous.and_then(|sid| {
                earlier
                    .get(&sid)
                    .filter(|i| {
                        let old = &evidence.snapshots[**i];
                        old.statement.region == snapshot.statement.region
                            && snapshot.base.is_none()
                            && old.base.is_none()
                            && old.statement.currency == snapshot.statement.currency
                            && !old.blocks.is_empty()
                            && old.blocks.len() < snapshot.blocks.len()
                            && snapshot.blocks.starts_with(&old.blocks)
                    })
                    .map(|i| (sid, *i))
            });
            let mut carried = snapshot.clone();
            let prefix = base.map(|(checkpoint, i)| {
                let blocks = evidence.snapshots[i].blocks.len();
                carried.blocks = snapshot.blocks[blocks..].to_vec();
                Prefix { checkpoint, blocks }
            });
            result.snapshots.push(CarriedSnapshot {
                prefix,
                snapshot: carried,
            });
            earlier.entry(snapshot.statement.id()?).or_insert(index);
        }
        Ok(result)
    }
    /// Syntax reconstruction only: callers must authenticate all expanded
    /// signatures, finality/eras, owners, value and dependencies from genesis.
    /// Nothing is loaded from a peer cache, disk orphan or current local ledger.
    pub fn expand(&self) -> Result<Evidence> {
        require(
            self.snapshots.len() <= MAX_SNAPSHOTS,
            "carried snapshot count bound",
        )?;
        let mut result = Evidence::default();
        let mut earlier: BTreeMap<Hash, usize> = BTreeMap::new();
        let mut expanded_bytes = 0usize;
        for (index, carried) in self.snapshots.iter().enumerate() {
            let mut snapshot = carried.snapshot.clone();
            require(snapshot.blocks.len() <= MAX_BLOCKS, "carried block bound")?;
            if let Some(prefix) = &carried.prefix {
                let i = *earlier
                    .get(&prefix.checkpoint)
                    .ok_or("carried prefix lacks exact earlier checkpoint")?;
                let old = &result.snapshots[i];
                let count = prefix
                    .blocks
                    .checked_add(snapshot.blocks.len())
                    .ok_or("carried prefix block overflow")?;
                require(
                    prefix.blocks > 0
                        && prefix.blocks == old.blocks.len()
                        && old.statement.height == prefix.blocks as u64
                        && !snapshot.blocks.is_empty()
                        && count <= MAX_BLOCKS
                        && snapshot.statement.height == count as u64
                        && snapshot.statement.previous == Some(prefix.checkpoint)
                        && snapshot.statement.currency == old.statement.currency
                        && snapshot.statement.region == old.statement.region,
                    "carried prefix domain, predecessor or block range",
                )?;
                let prefix_bytes = serde_json::to_vec(&old.blocks)
                    .map_err(|e| e.to_string())?
                    .len();
                let suffix_bytes = serde_json::to_vec(&snapshot)
                    .map_err(|e| e.to_string())?
                    .len();
                require(
                    prefix_bytes
                        .checked_add(suffix_bytes)
                        .is_some_and(|n| n <= MAX_BYTES + 1),
                    "carried prefix expansion byte bound",
                )?;
                let mut blocks = old.blocks.clone();
                blocks.append(&mut snapshot.blocks);
                snapshot.blocks = blocks;
            }
            expanded_bytes = expanded_bytes
                .checked_add(
                    serde_json::to_vec(&snapshot)
                        .map_err(|e| e.to_string())?
                        .len(),
                )
                .ok_or("carried expanded evidence overflow")?;
            require(
                expanded_bytes <= MAX_BYTES,
                "carried expanded evidence byte bound",
            )?;
            earlier.entry(snapshot.statement.id()?).or_insert(index);
            result.snapshots.push(snapshot);
        }
        encode("evidence", &result)?;
        Ok(result)
    }
}
