//! Local-only encrypted custody. Passwords never enter argv, env or HTTP.
use crate::store::{atomic_replace, private_create, read_bounded, sync_dir};
use anyhow::{Context, Result, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signer, SigningKey};
use fs2::FileExt;
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use rld_protocol::{
    codec::{Blob, Id, decode, encode, hash, tagged},
    crypto,
    model::*,
    record,
};
use sha2::Sha256;
use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

const MAX_VAULT: usize = 256 * 1024 * 1024;
record!(Binding {currency:Id  =>  0,domain:Id  =>  1,identity:Id  =>  2,epoch:u64  =>  3,pool_epoch:u64  =>  4,purpose:String  =>  5});
record!(Envelope {format:String  =>  0,binding:Binding  =>  1,salt:Blob  =>  2,nonce:Blob  =>  3,generation:u64  =>  4,ciphertext:Blob  =>  5});
record!(Approval {scope:Id => 0,message:Id => 1,signature:Signature => 2});
record!(SignedResponse {vote:Vote => 0,context:Blob => 1});
record!(Secret {binding:Binding  =>  0,identity_seed:Blob  =>  1,native_seed:Blob  =>  2,native_offset:u32  =>  3,controller_seeds:Vec<Blob>  =>  4,inventory:PublicInventory  =>  5,responses:Vec<SignedResponse> => 6,transport_sequence:u64  =>  7,approvals:Vec<Approval> => 8});
impl Drop for Secret {
    fn drop(&mut self) {
        self.identity_seed.0.zeroize();
        self.native_seed.0.zeroize();
        for s in &mut self.controller_seeds {
            s.0.zeroize();
        }
    }
}
pub struct Vault {
    path: PathBuf,
    head: PathBuf,
    _lock: File,
    key: Zeroizing<[u8; 32]>,
    salt: Blob,
    generation: u64,
    secret: Secret,
    poisoned: bool,
    trees: std::cell::RefCell<std::collections::BTreeMap<(Id, bool), Vec<Vec<Id>>>>,
}

fn key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(
        !password.is_empty() && password.len() <= 4096 && salt.len() == 32,
        "password/salt bounds"
    );
    let mut key = Zeroizing::new([0; 32]);
    let p = Params::new(65536, 3, 1, Some(32)).map_err(|e| anyhow::anyhow!("{e}"))?;
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password, salt, &mut *key)
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(key)
}
fn random() -> Id {
    let mut b = [0; 32];
    OsRng.fill_bytes(&mut b);
    Id(b)
}
pub fn public(seed: &[u8]) -> Result<Id> {
    let seed: &[u8; 32] = seed.try_into().map_err(|_| anyhow::anyhow!("seed size"))?;
    Ok(Id(SigningKey::from_bytes(seed).verifying_key().to_bytes()))
}
fn sign(seed: &[u8], bytes: &[u8]) -> Result<Signature> {
    let seed: &[u8; 32] = seed.try_into().map_err(|_| anyhow::anyhow!("seed size"))?;
    let sk = SigningKey::from_bytes(seed);
    Ok(Signature {
        key: Id(sk.verifying_key().to_bytes()),
        bytes: Blob(sk.sign(bytes).to_bytes().to_vec()),
    })
}
fn native_key(binding: &Binding, seed: &[u8], index: u32) -> Result<Zeroizing<[u8; 32]>> {
    let salt = hash(
        "RLD-KEY-EPOCH",
        binding.currency,
        &(binding.domain, binding.identity, binding.epoch),
    );
    let info = tagged(
        "RLD-NATIVE-ED25519-SEED",
        binding.currency,
        &(binding.domain, binding.identity, binding.epoch, index),
    );
    let mut out = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(&salt.0), seed)
        .expand(&info, &mut *out)
        .map_err(|_| anyhow::anyhow!("key derivation"))?;
    Ok(out)
}
fn evolve(binding: &Binding, seed: &[u8], index: u32) -> Id {
    // Encode directly into zeroized storage; do not create a temporary Blob
    // containing a second untracked copy of a monetary seed.
    let mut bytes = Zeroizing::new(Vec::new());
    let mut e = minicbor::Encoder::new(&mut *bytes);
    e.array(8)
        .unwrap()
        .str("RLD-KEY-NEXT")
        .unwrap()
        .str(rld_protocol::PROTOCOL)
        .unwrap()
        .bytes(&binding.currency.0)
        .unwrap()
        .bytes(&binding.domain.0)
        .unwrap()
        .bytes(&binding.identity.0)
        .unwrap()
        .u64(binding.epoch)
        .unwrap()
        .u32(index)
        .unwrap()
        .bytes(seed)
        .unwrap();
    Id::digest(&bytes)
}
fn aad(e: &Envelope) -> Vec<u8> {
    tagged(
        "RLD-ENCRYPTED-CUSTODY",
        e.binding.currency,
        &(
            &e.format,
            &e.binding,
            &e.salt,
            &e.nonce,
            e.generation,
            "argon2id-v19-m65536-t3-p1",
            "xchacha20poly1305",
        ),
    )
}
fn encrypted(secret: &Secret, salt: Blob, key: &[u8; 32], generation: u64) -> Result<Vec<u8>> {
    let mut nonce = vec![0; 24];
    OsRng.fill_bytes(&mut nonce);
    let mut e = Envelope {
        format: "RLD-CUSTODY-1".into(),
        binding: secret.binding.clone(),
        salt,
        nonce: Blob(nonce),
        generation,
        ciphertext: Blob(vec![]),
    };
    let plaintext = Zeroizing::new(encode(secret));
    e.ciphertext = Blob(
        XChaCha20Poly1305::new(key.into())
            .encrypt(
                XNonce::from_slice(&e.nonce.0),
                Payload {
                    msg: &plaintext,
                    aad: &aad(&e),
                },
            )
            .map_err(|_| anyhow::anyhow!("custody encryption"))?,
    );
    let bytes = encode(&e);
    ensure!(
        bytes.len() <= MAX_VAULT,
        "private custody capacity exhausted before publication"
    );
    Ok(bytes)
}

impl Vault {
    pub fn create_wallet(path: &Path, head: &Path, password: &[u8]) -> Result<Id> {
        let seed = random();
        let identity = public(&seed.0)?;
        let binding = Binding {
            currency: Id::ZERO,
            domain: Id::ZERO,
            identity,
            epoch: 0,
            pool_epoch: 0,
            purpose: "wallet-identity".into(),
        };
        let secret = Secret {
            binding,
            identity_seed: Blob(seed.0.to_vec()),
            native_seed: Blob(vec![]),
            native_offset: 0,
            controller_seeds: vec![],
            inventory: PublicInventory {
                validator: identity,
                native: vec![],
                controller: vec![],
            },
            responses: vec![],
            transport_sequence: 0,
            approvals: vec![],
        };
        Self::create(path, head, password, secret)?;
        Ok(identity)
    }
    pub fn create_validator(
        path: &Path,
        head: &Path,
        password: &[u8],
        binding: Binding,
        identity_seed: &Vault,
    ) -> Result<PublicInventory> {
        ensure!(
            binding.purpose == "validator"
                && identity_seed.secret.binding.purpose == "wallet-identity"
                && identity_seed.secret.binding.identity == binding.identity,
            "validator identity custody"
        );
        let initial = Zeroizing::new(random().0);
        let mut native_seed = Zeroizing::new(initial.to_vec());
        let mut native = Vec::with_capacity(rld_protocol::KEY_COUNT as usize);
        for i in 0..rld_protocol::KEY_COUNT {
            let sk = native_key(&binding, &native_seed, i)?;
            native.push(public(&*sk)?);
            let next = evolve(&binding, &native_seed, i);
            native_seed.zeroize();
            native_seed = Zeroizing::new(next.0.to_vec());
        }
        let mut controller_seeds = Vec::with_capacity(rld_protocol::KEY_COUNT as usize);
        let mut controller = Vec::with_capacity(rld_protocol::KEY_COUNT as usize);
        for _ in 0..rld_protocol::KEY_COUNT {
            let seed = random();
            controller.push(public(&seed.0)?);
            controller_seeds.push(Blob(seed.0.to_vec()));
        }
        let inventory = PublicInventory {
            validator: binding.identity,
            native,
            controller,
        };
        let secret = Secret {
            binding,
            identity_seed: identity_seed.secret.identity_seed.clone(),
            native_seed: Blob(initial.to_vec()),
            native_offset: 0,
            controller_seeds,
            inventory: inventory.clone(),
            responses: vec![],
            transport_sequence: 0,
            approvals: vec![],
        };
        Self::create(path, head, password, secret)?;
        Ok(inventory)
    }
    fn create(path: &Path, head: &Path, password: &[u8], secret: Secret) -> Result<()> {
        ensure!(
            !path.exists() && !head.exists(),
            "fresh custody files required"
        );
        let salt = Blob(random().0.to_vec());
        let key = key(password, &salt.0)?;
        let bytes = encrypted(&secret, salt, &key, 0)?;
        private_create(path, &bytes)?;
        sync_dir(path.parent().context("key parent")?)?;
        private_create(head, &encode(&Id::digest(&bytes)))?;
        sync_dir(head.parent().context("key head parent")?)?;
        Ok(())
    }
    pub fn recover_publication(path: &Path, head: &Path, password: &[u8]) -> Result<()> {
        ensure!(
            path != head && !path.is_symlink() && !head.is_symlink(),
            "custody recovery paths"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("lock"))?;
        lock.try_lock_exclusive()?;
        let pending = path.with_extension("pending");
        let (old, new, generation): (Id, Id, u64) = decode(&read_bounded(&pending, 256)?, 256)?;
        let disk = Id::digest(&read_bounded(path, MAX_VAULT)?);
        let latest: Id = decode(&read_bounded(head, 128)?, 128)?;
        ensure!(
            (disk == old || disk == new)
                && (latest == old || latest == new)
                && !(disk == old && latest == new),
            "custody recovery freshness"
        );
        let next = path.with_extension("next");
        if disk == old && !next.exists() {
            ensure!(
                latest == old && !head.with_extension("next").exists(),
                "inconsistent incomplete approval"
            );
        } else {
            let bytes = read_bounded(if disk == old { &next } else { path }, MAX_VAULT)?;
            ensure!(Id::digest(&bytes) == new, "custody publication changed");
            let envelope: Envelope = decode(&bytes, MAX_VAULT)?;
            ensure!(
                envelope.format == "RLD-CUSTODY-1"
                    && envelope.nonce.0.len() == 24
                    && envelope.generation == generation,
                "custody recovery envelope"
            );
            let key = key(password, &envelope.salt.0)?;
            let clear = Zeroizing::new(
                XChaCha20Poly1305::new((&*key).into())
                    .decrypt(
                        XNonce::from_slice(&envelope.nonce.0),
                        Payload {
                            msg: &envelope.ciphertext.0,
                            aad: &aad(&envelope),
                        },
                    )
                    .map_err(|_| anyhow::anyhow!("custody authentication failed"))?,
            );
            let secret: Secret = decode(&clear, MAX_VAULT)?;
            ensure!(
                secret.binding == envelope.binding
                    && public(&secret.identity_seed.0)? == secret.binding.identity,
                "recovery identity"
            );
            if disk == old {
                fs::rename(&next, path)?;
                sync_dir(path.parent().context("custody parent")?)?;
            } else {
                ensure!(!next.exists(), "ambiguous custody residue");
            }
            let head_next = head.with_extension("next");
            if head_next.exists() {
                ensure!(
                    read_bounded(&head_next, 128)? == encode(&new),
                    "changed pending head"
                );
                fs::rename(&head_next, head)?;
                sync_dir(head.parent().context("head parent")?)?;
            } else if latest != new {
                atomic_replace(head, &encode(&new))?;
            }
        }
        // Keep the original intent as a recoverability receipt. Recovery does
        // not create a new signature, select a block, or release a response.
        let retained = path.with_extension(format!("recovered-{generation}-{new}"));
        ensure!(!retained.exists(), "recovery residue already retained");
        fs::rename(pending, retained)?;
        sync_dir(path.parent().context("custody parent")?)?;
        Ok(())
    }
    pub fn open(path: &Path, head: &Path, password: &[u8]) -> Result<Self> {
        ensure!(
            !path.is_symlink()
                && !head.is_symlink()
                && path != head
                && !path.with_extension("next").exists()
                && !head.with_extension("next").exists()
                && !path.with_extension("pending").exists(),
            "custody requires unchanged latest head and no interrupted publication"
        );
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.with_extension("lock"))?;
        lock.try_lock_exclusive()?;
        let bytes = read_bounded(path, MAX_VAULT)?;
        let expected: Id = decode(&read_bounded(head, 128)?, 128)?;
        ensure!(
            Id::digest(&bytes) == expected,
            "custody latest-head mismatch"
        );
        let e: Envelope = decode(&bytes, MAX_VAULT)?;
        ensure!(
            e.format == "RLD-CUSTODY-1" && e.nonce.0.len() == 24 && e.salt.0.len() == 32,
            "custody envelope"
        );
        let key = key(password, &e.salt.0)?;
        let clear = Zeroizing::new(
            XChaCha20Poly1305::new((&*key).into())
                .decrypt(
                    XNonce::from_slice(&e.nonce.0),
                    Payload {
                        msg: &e.ciphertext.0,
                        aad: &aad(&e),
                    },
                )
                .map_err(|_| anyhow::anyhow!("wrong password or damaged custody"))?,
        );
        let secret: Secret = decode(&clear, MAX_VAULT)?;
        ensure!(
            secret.binding == e.binding && public(&secret.identity_seed.0)? == e.binding.identity,
            "custody purpose/identity mismatch"
        );
        Ok(Self {
            path: path.into(),
            head: head.into(),
            _lock: lock,
            key,
            salt: e.salt,
            generation: e.generation,
            secret,
            poisoned: false,
            trees: Default::default(),
        })
    }
    fn publish(&mut self) -> Result<()> {
        let old = Id::digest(&read_bounded(&self.path, MAX_VAULT)?);
        let latest: Id = decode(&read_bounded(&self.head, 128)?, 128)?;
        ensure!(
            old == latest && !self.path.with_extension("pending").exists(),
            "custody freshness/pending"
        );
        let next = self
            .generation
            .checked_add(1)
            .context("custody generation exhaustion")?;
        let bytes = encrypted(&self.secret, self.salt.clone(), &self.key, next)?;
        let new = Id::digest(&bytes);
        private_create(
            &self.path.with_extension("pending"),
            &encode(&(old, new, next)),
        )?;
        sync_dir(self.path.parent().context("custody parent")?)?;
        atomic_replace(&self.path, &bytes)?;
        atomic_replace(&self.head, &encode(&new))?;
        fs::remove_file(self.path.with_extension("pending"))?;
        sync_dir(self.path.parent().context("custody parent")?)?;
        self.generation = next;
        Ok(())
    }
    fn persist(&mut self) -> Result<()> {
        ensure!(
            !self.poisoned,
            "custody halted after incomplete publication"
        );
        let result = self.publish();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    pub fn binding(&self) -> &Binding {
        &self.secret.binding
    }
    pub fn inventory(&self) -> &PublicInventory {
        &self.secret.inventory
    }
    pub fn sign_owner(&self, owner: &Owner, message: &[u8]) -> Result<Signature> {
        ensure!(
            owner.keys.contains(&self.secret.binding.identity),
            "wallet not in owner policy"
        );
        sign(&self.secret.identity_seed.0, message)
    }
    pub fn sign_approval(&mut self, scope: Id, message: &[u8]) -> Result<Signature> {
        ensure!(!self.poisoned, "custody publication incomplete");
        let digest = Id::digest(message);
        if let Some(old) = self.secret.approvals.iter().find(|a| a.scope == scope) {
            ensure!(
                old.message == digest,
                "conflicting identity approval refused"
            );
            return Ok(old.signature.clone());
        }
        ensure!(
            self.secret.approvals.len() < 65536,
            "identity approval capacity"
        );
        let signature = sign(&self.secret.identity_seed.0, message)?;
        self.secret.approvals.push(Approval {
            scope,
            message: digest,
            signature: signature.clone(),
        });
        self.persist()?;
        Ok(signature)
    }
    pub fn sign_identity(&self, message: &[u8]) -> Result<Signature> {
        sign(&self.secret.identity_seed.0, message)
    }
    pub fn next_transport_sequence(&mut self) -> Result<u64> {
        self.secret.transport_sequence = self
            .secret
            .transport_sequence
            .checked_add(1)
            .context("transport sequence exhaustion")?;
        self.persist()?;
        Ok(self.secret.transport_sequence)
    }
    pub fn key_leaf(&self, config: &Configuration, pool: bool, index: u32) -> Result<KeyLeaf> {
        ensure!(
            config.currency == self.secret.binding.currency
                && config.domain == self.secret.binding.domain
                && config.epoch == self.secret.binding.epoch
                && config.pool_epoch == self.secret.binding.pool_epoch,
            "signer scope"
        );
        let keys = if pool {
            &self.secret.inventory.controller
        } else {
            &self.secret.inventory.native
        };
        ensure!(
            keys.len() == rld_protocol::KEY_COUNT as usize && index < rld_protocol::KEY_COUNT,
            "inventory index"
        );
        let cache_key = (config.id(), pool);
        let mut cache = self.trees.borrow_mut();
        if !cache.contains_key(&cache_key) {
            ensure!(cache.len() < 2, "custody public-tree cache scope");
            let mut levels = vec![
                keys.iter()
                    .enumerate()
                    .map(|(i, k)| {
                        crypto::key_leaf(config, self.secret.binding.identity, pool, i as u32, *k)
                    })
                    .collect::<Vec<_>>(),
            ];
            while levels.last().unwrap().len() > 1 {
                let next = levels
                    .last()
                    .unwrap()
                    .chunks_exact(2)
                    .map(|p| crypto::key_node(config.currency, p[0], p[1]))
                    .collect();
                levels.push(next);
            }
            cache.insert(cache_key, levels);
        }
        let levels = &cache[&cache_key];
        let mut position = index as usize;
        let mut path = Vec::with_capacity(16);
        for level in levels.iter().take(16) {
            path.push(level[position ^ 1]);
            position /= 2;
        }
        let leaf = KeyLeaf {
            validator: self.secret.binding.identity,
            key: keys[index as usize],
            path,
        };
        crypto::verify_leaf(config, &leaf, pool, index)?;
        Ok(leaf)
    }
    pub fn sign_vote(
        &mut self,
        config: &Configuration,
        namespace: Id,
        pool: Option<u32>,
        sequence: u64,
        view: u64,
        phase: u8,
        statement: Id,
        context: Blob,
    ) -> Result<Vote> {
        ensure!(
            !self.poisoned,
            "custody is not durable; recover before signing"
        );
        if let Some(old) = self.secret.responses.iter().find(|v| {
            v.vote.namespace == namespace
                && v.vote.sequence == sequence
                && v.vote.view == view
                && v.vote.phase == phase
        }) {
            ensure!(
                old.vote.statement == statement
                    && old.vote.configuration == config.id()
                    && old.context == context,
                "durable signer refuses conflicting intent"
            );
            return Ok(old.vote.clone());
        }
        let offset = if let Some(p) = pool {
            ensure!(sequence == 0, "controller sequence");
            p
        } else {
            u32::try_from(
                sequence
                    .checked_sub(config.first_sequence)
                    .context("key sequence")?,
            )?
        };
        let leaf = self.key_leaf(config, pool.is_some(), offset)?;
        let mut vote = Vote {
            currency: config.currency,
            namespace,
            configuration: config.id(),
            sequence,
            view,
            phase,
            statement,
            validator: self.secret.binding.identity,
            key: leaf,
            signature: Signature {
                key: Id::ZERO,
                bytes: Blob(vec![]),
            },
        };
        vote.signature = if let Some(index) = pool {
            let seed = self
                .secret
                .controller_seeds
                .get(index as usize)
                .context("pool key index")?;
            ensure!(seed.0.len() == 32, "controller key retired");
            sign(&seed.0, &crypto::vote_bytes(&vote))?
        } else {
            ensure!(
                offset == self.secret.native_offset,
                "native signing requires current unretired position"
            );
            let seed = native_key(&self.secret.binding, &self.secret.native_seed.0, offset)?;
            sign(&*seed, &crypto::vote_bytes(&vote))?
        };
        crypto::verify_vote(config, namespace, pool, &vote)?;
        self.secret.responses.push(SignedResponse {
            vote: vote.clone(),
            context,
        });
        self.persist()?;
        Ok(vote)
    }
    pub fn retire_native(
        &mut self,
        config: &Configuration,
        qc: &Quorum,
        statement: Id,
    ) -> Result<()> {
        crypto::verify_quorum(config, config.domain, None, qc, 3, statement)?;
        let sequence = qc.votes[0].sequence;
        let offset = u32::try_from(
            sequence
                .checked_sub(config.first_sequence)
                .context("native offset")?,
        )?;
        ensure!(offset == self.secret.native_offset, "retirement position");
        let next = evolve(&self.secret.binding, &self.secret.native_seed.0, offset);
        self.secret.native_seed.0.zeroize();
        self.secret.native_seed = Blob(next.0.to_vec());
        self.secret.native_offset = self
            .secret
            .native_offset
            .checked_add(1)
            .context("native key exhaustion")?;
        self.secret
            .responses
            .retain(|v| v.vote.namespace != config.domain || v.vote.sequence != sequence);
        self.persist()
    }
    pub fn retire_controller(
        &mut self,
        config: &Configuration,
        id: Id,
        index: u32,
        qc: &Quorum,
        statement: Id,
    ) -> Result<()> {
        crypto::verify_quorum(config, id, Some(index), qc, 3, statement)?;
        let seed = self
            .secret
            .controller_seeds
            .get_mut(index as usize)
            .context("controller key")?;
        if seed.0.is_empty() {
            return Ok(());
        }
        seed.0.zeroize();
        seed.0.clear();
        self.secret.responses.retain(|v| v.vote.namespace != id);
        self.persist()
    }
    pub fn reconcile_native(
        &mut self,
        config: &Configuration,
        qc: &Quorum,
        statement: Id,
    ) -> Result<()> {
        let offset = u32::try_from(
            qc.votes
                .first()
                .context("empty native QC")?
                .sequence
                .checked_sub(config.first_sequence)
                .context("native position")?,
        )?;
        if offset < self.secret.native_offset {
            return Ok(());
        }
        self.retire_native(config, qc, statement)
    }
    pub fn pending_responses(&self) -> &[SignedResponse] {
        &self.secret.responses
    }
}
