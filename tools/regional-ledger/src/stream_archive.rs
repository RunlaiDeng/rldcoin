//! Compact disk codec for the separate read-only stream verifier. Only repeated
//! currency/region fields are supplied by pinned, fully verified genesis. Every
//! original native block/intent/signature is reconstructed and normally replayed.
//! No checkpoint, ledger, signing custody or ordinary store is created/adopted.
use super::*;
use crate::stream_replay::{Cursor, Head, Record as NativeRecord};

pub const FORMAT: &str = "RLD-NATIVE-STREAM-COMPACT-V1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub format: String,
    pub currency: Hash,
    pub region: Hash,
    pub trust: Hash,
}
impl Binding {
    pub fn new(trust: &Trust, region: &str) -> Result<Self> {
        let region = trust.named(region)?;
        // Do not silently turn BFT or epoch histories into initial PoW.
        Cursor::new(region, trust)?;
        Ok(Self {
            format: FORMAT.into(),
            currency: trust.currency()?,
            region,
            trust: trust.binding,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactIntent {
    inputs: Vec<Hash>,
    outputs: Vec<Payment>,
    fee: Amount,
    destination: Option<Hash>,
    remote: Option<Payment>,
    destination_fee: Amount,
    valid_through: u64,
    approvals: Vec<Approval>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CompactCommand {
    Spend(Box<CompactIntent>),
    Import { snapshot: Hash, export: Hash },
    Reconfigure(Box<joint_epoch::Plan>),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactBlock {
    parent: Hash,
    anchor: Option<Hash>,
    height: u64,
    miner: String,
    command_root: Hash,
    state: Hash,
    nonce: u64,
    commands: Vec<CompactCommand>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Record {
    Binding { binding: Binding },
    Evidence { evidence: Evidence },
    Block { block: Box<CompactBlock> },
    Finalize { checkpoint: Hash },
}

impl Record {
    /// Encoding alone grants no native authority. Reject inconsistent omitted
    /// fields, retain all other original fields and every ordered approval.
    pub fn from_native(record: NativeRecord, binding: &Binding) -> Result<Self> {
        require(binding.format == FORMAT, "compact archive format")?;
        let result = match record {
            NativeRecord::Evidence { evidence } => Self::Evidence { evidence },
            NativeRecord::Finalize { checkpoint } => Self::Finalize { checkpoint },
            NativeRecord::Block { block } => {
                require(
                    block.header.currency == binding.currency
                        && block.header.region == binding.region,
                    "compact block differs from pinned domain",
                )?;
                require(block.commands.len() <= MAX_COMMANDS, "command bound")?;
                let mut commands = Vec::with_capacity(block.commands.len());
                for command in block.commands {
                    commands.push(match command {
                        Command::Spend(signed) => {
                            let intent = signed.intent;
                            require(
                                intent.currency == binding.currency
                                    && intent.region == binding.region,
                                "compact intent differs from pinned domain",
                            )?;
                            CompactCommand::Spend(Box::new(CompactIntent {
                                inputs: intent.inputs,
                                outputs: intent.outputs,
                                fee: intent.fee,
                                destination: intent.destination,
                                remote: intent.remote,
                                destination_fee: intent.destination_fee,
                                valid_through: intent.valid_through,
                                approvals: signed.approvals,
                            }))
                        }
                        Command::Import { snapshot, export } => {
                            CompactCommand::Import { snapshot, export }
                        }
                        Command::Reconfigure(plan) => CompactCommand::Reconfigure(plan),
                    });
                }
                let h = block.header;
                Self::Block {
                    block: Box::new(CompactBlock {
                        parent: h.parent,
                        anchor: h.anchor,
                        height: h.height,
                        miner: h.miner,
                        command_root: h.commands,
                        state: h.state,
                        nonce: h.nonce,
                        commands,
                    }),
                }
            }
        };
        // Enforce both disk and expanded complete native record bounds.
        result.line()?;
        result.expand(binding)?;
        Ok(result)
    }

    pub fn line(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        require(bytes.len() < MAX_BYTES, "compact stream record bound")?;
        bytes.push(b'\n');
        Ok(bytes)
    }

    pub(crate) fn expand(&self, binding: &Binding) -> Result<Option<NativeRecord>> {
        let record = match self {
            Self::Binding { .. } => return Ok(None),
            Self::Evidence { evidence } => NativeRecord::Evidence {
                evidence: evidence.clone(),
            },
            Self::Finalize { checkpoint } => NativeRecord::Finalize {
                checkpoint: *checkpoint,
            },
            Self::Block { block } => {
                require(block.commands.len() <= MAX_COMMANDS, "command bound")?;
                let mut commands = Vec::with_capacity(block.commands.len());
                for command in &block.commands {
                    commands.push(match command {
                        CompactCommand::Spend(intent) => Command::Spend(Box::new(SignedIntent {
                            intent: Intent {
                                currency: binding.currency,
                                region: binding.region,
                                inputs: intent.inputs.clone(),
                                outputs: intent.outputs.clone(),
                                fee: intent.fee,
                                destination: intent.destination,
                                remote: intent.remote.clone(),
                                destination_fee: intent.destination_fee,
                                valid_through: intent.valid_through,
                            },
                            approvals: intent.approvals.clone(),
                        })),
                        CompactCommand::Import { snapshot, export } => Command::Import {
                            snapshot: *snapshot,
                            export: *export,
                        },
                        CompactCommand::Reconfigure(plan) => Command::Reconfigure(plan.clone()),
                    });
                }
                NativeRecord::Block {
                    block: Box::new(Block {
                        header: Header {
                            currency: binding.currency,
                            region: binding.region,
                            parent: block.parent,
                            anchor: block.anchor,
                            height: block.height,
                            miner: block.miner.clone(),
                            commands: block.command_root,
                            state: block.state,
                            nonce: block.nonce,
                        },
                        commands,
                    }),
                }
            }
        };
        require(
            serde_json::to_vec(&record)
                .map_err(|e| e.to_string())?
                .len()
                < MAX_BYTES,
            "expanded complete stream record bound",
        )?;
        Ok(Some(record))
    }
}

pub fn check_archive(
    path: &std::path::Path,
    bootstrap: &Bootstrap,
    authority: &str,
    currency: Hash,
    region: &str,
    expected_head: Hash,
) -> Result<Head> {
    let trust = Trust::verify(bootstrap, authority, currency)?;
    let binding = Binding::new(&trust, region)?;
    let mut first = true;
    let result =
        stream_replay::check_archive_records(path, &trust, region, expected_head, |line| {
            let record: Record = serde_json::from_slice(line).map_err(|e| e.to_string())?;
            require(record.line()? == line, "noncanonical compact stream record")?;
            if first {
                require(
                    matches!(&record, Record::Binding { binding: value } if value == &binding),
                    "complete pinned compact archive binding must be first",
                )?;
                first = false;
                Ok(None)
            } else {
                require(
                    !matches!(&record, Record::Binding { .. }),
                    "repeated compact archive binding",
                )?;
                record.expand(&binding)
            }
        })?;
    require(!first, "missing compact archive binding")?;
    Ok(result)
}
