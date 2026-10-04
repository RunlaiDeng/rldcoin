//! Native ordered state indexes. A proof authenticates a record only against
//! an already completely replayed certified state; it never authorizes import,
//! spending, finality, freshness or removal of a permanent tombstone.
use super::*;

pub const FORMAT: &str = "RLD-REGIONAL-STATE-COMMITMENT-V1";
pub const MAX_PROOF_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Collection {
    Coins,
    Exports,
    Imports,
}
impl Collection {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "coins" => Ok(Self::Coins),
            "exports" => Ok(Self::Exports),
            "imports" => Ok(Self::Imports),
            _ => Err("unknown state index collection".into()),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IndexRoot {
    pub entries: u64,
    pub tree: Hash,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Commitment {
    pub format: String,
    pub coins: IndexRoot,
    pub exports: IndexRoot,
    pub imports: IndexRoot,
    pub minted: Amount,
    pub received: Amount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_state: Option<Hash>,
}
impl Commitment {
    pub fn from_ledger(ledger: &Ledger) -> Result<Self> {
        Ok(crate::state_index::compute(ledger, None)?.0)
    }
    /// Independent full reconstruction, also used to compare incremental work.
    /// A commitment calculation does not authenticate a deserialized ledger.
    pub fn from_ledger_uncached(ledger: &Ledger) -> Result<Self> {
        ledger.audit()?;
        Ok(Self {
            format: FORMAT.into(),
            coins: index_root(Collection::Coins, &ledger.coins)?,
            exports: index_root(Collection::Exports, &ledger.exports)?,
            imports: index_root(Collection::Imports, &ledger.imports)?,
            minted: ledger.minted,
            received: ledger.received,
            channel_state: ledger
                .channel_state
                .as_deref()
                .map(channels::NativeState::commitment)
                .transpose()?,
        })
    }
    pub fn hash(&self) -> Result<Hash> {
        require(self.format == FORMAT, "state commitment version")?;
        for kind in [Collection::Coins, Collection::Exports, Collection::Imports] {
            let root = self.index(kind);
            require(root.entries <= MAX_COINS as u64, "state index count bound")?;
            if root.entries == 0 {
                require(root.tree == empty(kind)?, "empty state index root")?;
            }
        }
        // This hashes counters; only full native Ledger::audit/replay proves
        // conservation. Deserializing these counters is never that proof.
        id("state-index-commitment-v1", self)
    }
    fn index(&self, kind: Collection) -> &IndexRoot {
        match kind {
            Collection::Coins => &self.coins,
            Collection::Exports => &self.exports,
            Collection::Imports => &self.imports,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "record",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Value {
    Coins(Coin),
    Exports(Export),
    Imports(Hash),
}
impl Value {
    pub(crate) fn leaf(&self, kind: Collection, key: Hash) -> Result<Hash> {
        match (kind, self) {
            (Collection::Coins, Self::Coins(v)) => leaf(kind, key, v),
            (Collection::Exports, Self::Exports(v)) => leaf(kind, key, v),
            (Collection::Imports, Self::Imports(v)) => leaf(kind, key, v),
            _ => Err("state proof record collection mismatch".into()),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub key: Hash,
    pub value: Value,
    pub index: u64,
    pub siblings: Vec<Hash>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Witness {
    Present {
        member: Box<Member>,
    },
    Absent {
        lower: Option<Box<Member>>,
        upper: Option<Box<Member>>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub state: Commitment,
    pub collection: Collection,
    pub key: Hash,
    pub witness: Witness,
}
impl Proof {
    pub fn from_ledger(ledger: &Ledger, collection: Collection, key: Hash) -> Result<Self> {
        let (state, prepared, _) = crate::state_index::compute(ledger, Some(collection))?;
        let prepared = prepared.ok_or("state proof index missing")?;
        let values = prepared.values;
        let levels = prepared.levels;
        let make = |index: usize| -> Result<Box<Member>> {
            let mut cursor = index;
            let mut siblings = vec![];
            for (depth, level) in levels
                .iter()
                .take(levels.len().saturating_sub(1))
                .enumerate()
            {
                siblings.push(match level.get(cursor ^ 1) {
                    Some(hash) => *hash,
                    None => padding(collection, depth)?,
                });
                cursor /= 2;
            }
            Ok(Box::new(Member {
                key: values[index].0,
                value: values[index].1.clone(),
                index: index as u64,
                siblings,
            }))
        };
        let witness = match values.binary_search_by_key(&key, |(k, _)| *k) {
            Ok(i) => Witness::Present { member: make(i)? },
            Err(i) => Witness::Absent {
                lower: i.checked_sub(1).map(make).transpose()?,
                upper: (i < values.len()).then(|| make(i)).transpose()?,
            },
        };
        let proof = Self {
            state,
            collection,
            key,
            witness,
        };
        proof.verify(proof.state.hash()?, collection, key)?;
        Ok(proof)
    }
    /// expected_state must come from a native-replayed exact certificate.
    /// expected collection/key must come from the caller, never the proof.
    pub fn verify(
        &self,
        expected_state: Hash,
        collection: Collection,
        key: Hash,
    ) -> Result<Option<Value>> {
        require(
            encode("state-record-proof", self)?.len() <= MAX_PROOF_BYTES,
            "state proof byte bound",
        )?;
        require(
            self.collection == collection
                && self.key == key
                && self.state.hash()? == expected_state,
            "state proof root or query mismatch",
        )?;
        let root = self.state.index(collection);
        match &self.witness {
            Witness::Present { member } => {
                require(member.key == key, "state member query mismatch")?;
                verify_member(member, collection, root)?;
                Ok(Some(member.value.clone()))
            }
            Witness::Absent { lower, upper } => {
                if root.entries == 0 {
                    require(
                        lower.is_none() && upper.is_none(),
                        "empty state absence witnesses",
                    )?;
                    return Ok(None);
                }
                if let Some(m) = lower {
                    verify_member(m, collection, root)?;
                    require(m.key < key, "state absence lower key")?;
                }
                if let Some(m) = upper {
                    verify_member(m, collection, root)?;
                    require(key < m.key, "state absence upper key")?;
                }
                require(
                    match (lower, upper) {
                        (Some(a), Some(b)) => a.index.checked_add(1) == Some(b.index),
                        (None, Some(b)) => b.index == 0,
                        (Some(a), None) => a.index.checked_add(1) == Some(root.entries),
                        _ => false,
                    },
                    "state absence adjacent range",
                )?;
                Ok(None)
            }
        }
    }
}
fn leaf<T: Serialize>(kind: Collection, key: Hash, value: &T) -> Result<Hash> {
    id("state-index-leaf-v1", &(kind, key, value))
}
pub(crate) fn empty(kind: Collection) -> Result<Hash> {
    id("state-index-empty-v1", &kind)
}
pub(crate) fn padding(kind: Collection, depth: usize) -> Result<Hash> {
    id("state-index-padding-v1", &(kind, depth))
}
pub(crate) fn branch(kind: Collection, depth: usize, left: Hash, right: Hash) -> Result<Hash> {
    id("state-index-branch-v1", &(kind, depth, left, right))
}
pub(crate) fn levels(kind: Collection, leaves: Vec<Hash>) -> Result<Vec<Vec<Hash>>> {
    require(leaves.len() <= MAX_COINS, "state index count bound")?;
    let mut result = vec![leaves];
    while result.last().is_some_and(|v| v.len() > 1) {
        let depth = result.len() - 1;
        let mut next = vec![];
        for pair in result[depth].chunks(2) {
            next.push(branch(
                kind,
                depth,
                pair[0],
                match pair.get(1) {
                    Some(h) => *h,
                    None => padding(kind, depth)?,
                },
            )?);
        }
        result.push(next);
    }
    Ok(result)
}
fn index_root<T: Serialize>(kind: Collection, values: &BTreeMap<Hash, T>) -> Result<IndexRoot> {
    let leaves = values
        .iter()
        .map(|(key, value)| leaf(kind, *key, value))
        .collect::<Result<Vec<_>>>()?;
    let levels = levels(kind, leaves)?;
    let tree = match levels.last().and_then(|v| v.first()) {
        Some(h) => *h,
        None => empty(kind)?,
    };
    Ok(IndexRoot {
        entries: values.len() as u64,
        tree,
    })
}
fn verify_member(member: &Member, kind: Collection, root: &IndexRoot) -> Result<()> {
    require(
        root.entries > 0 && root.entries <= MAX_COINS as u64 && member.index < root.entries,
        "state member index bound",
    )?;
    let mut width = root.entries;
    let mut expected_levels = 0;
    while width > 1 {
        width = width.div_ceil(2);
        expected_levels += 1;
    }
    require(
        member.siblings.len() == expected_levels,
        "state member path length",
    )?;
    let mut hash = member.value.leaf(kind, member.key)?;
    let mut cursor = member.index;
    width = root.entries;
    for (depth, sibling) in member.siblings.iter().enumerate() {
        if cursor ^ 1 >= width {
            require(
                *sibling == padding(kind, depth)?,
                "state member odd padding",
            )?;
        }
        hash = if cursor.is_multiple_of(2) {
            branch(kind, depth, hash, *sibling)?
        } else {
            branch(kind, depth, *sibling, hash)?
        };
        cursor /= 2;
        width = width.div_ceil(2);
    }
    require(hash == root.tree, "state member root mismatch")
}
