//! PUBLIC NO-VALUE native fixture keys only. Generated encrypted material and
//! private caller/head/native state stay local and never migrate to real funds.
#[allow(dead_code)]
#[path = "support/fast_funding.rs"]
mod support;
use rld_survivor_node::{
    fast_payment::Payment,
    fast_session::{Action, FeePolicy, Id, OnchainRequest, Session},
    kernel::{fast, Hash},
    keyfile,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
const PASSWORD: &[u8] = b"public no-value bounded fee-wallet password";
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
fn write(p: &Path, raw: &[u8]) {
    let mut o = fs::OpenOptions::new();
    o.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p).unwrap();
    f.write_all(raw).unwrap();
    f.sync_all().unwrap();
}
fn id(v: &Value, k: &str) -> Id {
    serde_json::from_value(v[k].clone()).unwrap()
}
fn rid(n: &mut u64) -> Id {
    *n += 1;
    let mut b = [0; 32];
    b[..8].copy_from_slice(&n.to_be_bytes());
    Id(b)
}
struct Test {
    f: support::Fixture,
    root: PathBuf,
    node: PathBuf,
    head: PathBuf,
    key: PathBuf,
    s: Session,
    n: u64,
    terms: FeePolicy,
    proofs: [Vec<u8>; 2],
    deadline: Instant,
}
impl Test {
    fn new(label: &str, limit: u16) -> Self {
        Self::aged(label, limit, 61200)
    }
    fn aged(label: &str, limit: u16, age: u64) -> Self {
        let deadline = Instant::now() + Duration::from_secs(180);
        let mut f = support::aged_fixture(age);
        let chain = f.ledger.chain_id();
        let root = std::env::temp_dir().join(format!(
            "rld-fee-policy-{}-{}-{label}",
            std::process::id(),
            hex::encode(chain)
        ));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let origin = f.ledger.funding_origin(f.channel).unwrap();
        let first = Payment::verify(&origin, &support::payment(&f, None, 0, 70, 111)).unwrap();
        let second =
            Payment::verify(&origin, &support::payment(&f, Some(&first), 1, 25, 112)).unwrap();
        let proofs = [
            first.after_certificate().to_vec(),
            second.after_certificate().to_vec(),
        ];
        let input = support::out(f.channel, 1);
        let change = f.ledger.coins()[&input].amount - 1;
        let close = support::action(&f, 2, &f.owners[1], (&input, change), &[], 113);
        let miner = f.miner.verifying_key().to_bytes();
        let block = support::mine_until(&mut f.ledger, miner, vec![close], f.now, deadline);
        f.history.extend((block.len() as u32).to_be_bytes());
        f.history.extend(block);
        let node = root.join("session");
        let head = root.join("head");
        let mut s = Session::create_controlled(&node, &f.genesis, chain, &head, now()).unwrap();
        let mut n = 0;
        let mut at = 0;
        while at < f.history.len() {
            let size = u32::from_be_bytes(f.history[at..at + 4].try_into().unwrap()) as usize;
            at += 4;
            let a = Action::Native {
                tip: Id(s.tip()),
                block: hex::encode(&f.history[at..at + size]),
            };
            at += size;
            let out = s.execute(rid(&mut n), s.head(), a, None, now()).unwrap();
            assert!(out["diagnostic"].is_null(), "{out}");
            assert!(Instant::now() < deadline);
        }
        let terms = FeePolicy {
            chain: Id(chain),
            caller: Id(s.caller_binding()),
            owner: Id(f.owners[0].verifying_key().to_bytes()),
            channels: vec![Id(f.channel)],
            inputs: vec![hex::encode(support::out(f.channel, 0))],
            max_fee: "1".into(),
            total_fee: limit.to_string(),
            max_operations: limit,
            expiry_height: (f.ledger.tip().height() + 10000).to_string(),
            expiry_time: (now() + 86400).to_string(),
            nonce: Id([114; 32]),
        };
        let key = root.join("fee.key");
        write(
            &key,
            &keyfile::encrypt(&f.owners[0], chain, PASSWORD).unwrap(),
        );
        write(&root.join("genesis"), &f.genesis);
        Self {
            f,
            root,
            node,
            head,
            key,
            s,
            n,
            terms,
            proofs,
            deadline,
        }
    }
    fn exec(&mut self, a: Action, password: Option<&[u8]>) -> (Id, Value) {
        let request = rid(&mut self.n);
        let out = self
            .s
            .execute(request, self.s.head(), a, password, now())
            .unwrap();
        assert!(Instant::now() < self.deadline);
        (request, out)
    }
    fn approve(&mut self) -> Id {
        let a = Action::FeePolicyApprove {
            tip: Id(self.s.tip()),
            terms: self.terms.clone(),
            key_file: self.key.to_string_lossy().into(),
            approved: true,
        };
        let (id, out) = self.exec(a, Some(PASSWORD));
        assert!(out["diagnostic"].is_null(), "{out}");
        let raw = hex::decode(out["fee_policy"]["policy_hex"].as_str().unwrap()).unwrap();
        let terms = serde_json::to_vec(&self.terms).unwrap();
        let mut frame = b"RLDFPOL1".to_vec();
        frame.extend([0, 1, 0, 1]);
        frame.extend((terms.len() as u32).to_be_bytes());
        frame.extend(terms);
        use ed25519_dalek::Signer;
        let signature = self.f.owners[0]
            .sign(&[b"RLD-FAST-FEE-POLICY-1/CONSENT\0".as_slice(), &frame].concat());
        frame.extend(signature.to_bytes());
        assert_eq!(frame, raw, "independent complete policy byte construction");
        assert!(raw.len() <= 1616);
        assert!(out["operation_hex"].is_null());
        id
    }
    fn plan(&self, kind: u8, input: Vec<u8>, proof: usize, nonce: u8) -> OnchainRequest {
        OnchainRequest {
            kind,
            channel: Id(self.f.channel),
            actor: self.terms.owner,
            inputs: vec![hex::encode(input)],
            fee: "1".into(),
            expiry: self.terms.expiry_height.clone(),
            nonce: Id([nonce; 32]),
            certificate: if kind == 5 {
                String::new()
            } else {
                hex::encode(&self.proofs[proof])
            },
            timestamp: (self.f.ledger.tip().timestamp() + 600).to_string(),
        }
    }
    fn prepare(&mut self, policy: Id, p: OnchainRequest) -> (Id, Id) {
        let (prepared, out) = self.exec(
            Action::FeePolicyPrepare {
                tip: Id(self.s.tip()),
                policy_request: policy,
                plan: p,
            },
            None,
        );
        assert!(out["diagnostic"].is_null(), "{out}");
        (prepared, id(&out, "review_digest"))
    }
    fn sign(&mut self, policy: Id, prepare: Id, review: Id) -> (Id, Vec<u8>) {
        let (request, out) = self.exec(
            Action::FeePolicySign {
                tip: Id(self.s.tip()),
                policy_request: policy,
                prepare_request: prepare,
                review,
                key_file: self.key.to_string_lossy().into(),
            },
            Some(PASSWORD),
        );
        assert!(out["diagnostic"].is_null(), "{out}");
        (
            request,
            hex::decode(out["operation_hex"].as_str().unwrap()).unwrap(),
        )
    }
    fn include(&mut self, raw: Vec<u8>) -> Vec<u8> {
        let miner = self.f.miner.verifying_key().to_bytes();
        let block = support::mine_until(
            &mut self.f.ledger,
            miner,
            vec![raw],
            self.f.now,
            self.deadline,
        );
        let (_, out) = self.exec(
            Action::Native {
                tip: Id(self.s.tip()),
                block: hex::encode(&block),
            },
            None,
        );
        assert!(out["diagnostic"].is_null(), "{out}");
        block
    }
    fn two_claims(&mut self, policy: Id) -> [Hash; 2] {
        let p = self.plan(4, support::out(self.f.channel, 0), 0, 115);
        let (prepared, review) = self.prepare(policy, p);
        let (signed, first) = self.sign(policy, prepared, review);
        let (_, duplicate) = self.exec(
            Action::FeePolicySign {
                tip: Id(self.s.tip()),
                policy_request: policy,
                prepare_request: prepared,
                review,
                key_file: self
                    .root
                    .join("missing-keyless-reproduction")
                    .to_string_lossy()
                    .into(),
            },
            None,
        );
        assert!(duplicate["diagnostic"].is_null(), "{duplicate}");
        assert_eq!(
            hex::decode(duplicate["operation_hex"].as_str().unwrap()).unwrap(),
            first
        );
        assert_eq!(
            self.s
                .fee_policy_status(self.s.head(), policy, now())
                .unwrap()["signed_fee_liability"],
            "1"
        );
        let op = fast::operation_id(&first);
        let submit = rid(&mut self.n);
        let head = self.s.head();
        let out = self
            .s
            .submit_authorized(head, submit, signed, now())
            .unwrap();
        assert!(out["diagnostic"].is_null());
        self.include(first);
        let p = self.plan(3, support::out(op, 0), 1, 116);
        let (prepared, review) = self.prepare(policy, p);
        let (_, second) = self.sign(policy, prepared, review);
        let second_id = fast::operation_id(&second);
        self.include(second);
        [op, second_id]
    }
}
#[test]
fn signed_fee_owner_policy_funds_native_claims_from_exact_change_and_survives_cold_replay() {
    let mut t = Test::new("claims", 3);
    let policy = t.approve();
    let ids = t.two_claims(policy);
    let status = t.s.fee_policy_status(t.s.head(), policy, now()).unwrap();
    assert_eq!(status["signed_fee_liability"], "2");
    assert_eq!(status["remaining_operations"], 1);
    assert_eq!(
        t.f.ledger.coins()[&support::out(ids[1], 0)].owner,
        t.terms.owner.0
    );
    let head = t.s.head();
    let tip = t.s.tip();
    drop(t.s);
    let mut s =
        Session::open_controlled(&t.node, &t.f.genesis, t.f.ledger.chain_id(), &t.head, now())
            .unwrap();
    assert_eq!(s.head(), head);
    assert_eq!(s.tip(), tip);
    assert_eq!(
        s.fee_policy_status(head, policy, now()).unwrap()["signed_fee_liability"],
        "2"
    );
    let origin = t.f.ledger.funding_origin(t.f.channel).unwrap();
    let context = rld_survivor_node::fast_fee_claims::Contract::decode(origin.context()).unwrap();
    let accounting = rld_survivor_node::fast_fee_claims::FeeFloors::new(context).accounting();
    assert_eq!(
        t.f.ledger.coins().values().map(|c| c.amount).sum::<u128>()
            + accounting.principal
            + accounting.reserved.iter().sum::<u128>(),
        t.f.ledger.issued()
    );
    assert!(Instant::now() < t.deadline);
}
#[test]
fn bounded_policy_claims_settle_to_the_funding_miner_and_require_exact_reward_maturity() {
    // Old logical genesis times exercise the unchanged joint height/time
    // window. This is not physical elapsed-time or continuous-service evidence.
    let mut t = Test::aged("mature-settlement", 3, 2_000_000);
    let closed = t.f.ledger.tip().height();
    let policy = t.approve();
    let ids = t.two_claims(policy);
    let miner = t.f.miner.verifying_key().to_bytes();
    while t.f.ledger.tip().height() < closed + 2016 {
        let raw = support::mine_until(&mut t.f.ledger, miner, vec![], t.f.now, t.deadline);
        let (_, out) = t.exec(
            Action::Native {
                tip: Id(t.s.tip()),
                block: hex::encode(raw),
            },
            None,
        );
        assert!(out["diagnostic"].is_null());
    }
    let principal =
        t.f.ledger
            .funding_origin(t.f.channel)
            .unwrap()
            .verify_certificate(&t.proofs[1])
            .unwrap()
            .balances;
    let plan = t.plan(5, support::out(ids[1], 0), 0, 142);
    let (prepare, review) = t.prepare(policy, plan);
    let (_, raw) = t.sign(policy, prepare, review);
    let settlement = fast::operation_id(&raw);
    t.include(raw);
    let height = t.f.ledger.tip().height();
    let coin = &t.f.ledger.coins()[&support::out(settlement, 5)];
    for (i, value) in principal.into_iter().enumerate() {
        let output = &t.f.ledger.coins()[&support::out(settlement, 1 + i as u16)];
        assert_eq!(
            (output.owner, output.amount),
            (t.f.owners[i].verifying_key().to_bytes(), value)
        );
    }
    assert_eq!(
        (coin.owner, coin.amount, coin.maturity),
        (miner, 5, height + 100)
    );
    assert_eq!(
        t.s.fee_policy_status(t.s.head(), policy, now()).unwrap()["signed_fee_liability"],
        "3"
    );
    let (spend, tx) = support::ordinary(
        t.f.ledger.chain_id(),
        &t.f.miner,
        &support::out(settlement, 5),
        &[(t.terms.owner.0, 4)],
    );
    assert!(t
        .f
        .ledger
        .mining_job(
            miner,
            vec![spend.clone()],
            t.f.ledger.tip().timestamp() + 600,
            t.f.now
        )
        .is_err());
    while t.f.ledger.tip().height() < height + 99 {
        let raw = support::mine_until(&mut t.f.ledger, miner, vec![], t.f.now, t.deadline);
        let (_, out) = t.exec(
            Action::Native {
                tip: Id(t.s.tip()),
                block: hex::encode(raw),
            },
            None,
        );
        assert!(out["diagnostic"].is_null());
    }
    t.include(spend);
    assert_eq!(t.f.ledger.coins()[&support::out(tx, 0)].amount, 4);
    assert_eq!(
        t.f.ledger.coins().values().map(|c| c.amount).sum::<u128>(),
        t.f.ledger.issued()
    );
    let tip = t.s.tip();
    drop(t.s);
    let mut s =
        Session::open_controlled(&t.node, &t.f.genesis, t.f.ledger.chain_id(), &t.head, now())
            .unwrap();
    assert_eq!(s.tip(), tip);
    assert_eq!(
        s.fee_policy_status(s.head(), policy, now()).unwrap()["signed_fee_liability"],
        "3"
    );
    assert!(
        Instant::now() < t.deadline,
        "original180 policy settlement and cold replay"
    );
}
#[test]
fn independent_public_policy_vector_requires_exact_signature_scope_and_canonical_terms() {
    let v: Value = serde_json::from_str(include_str!(
        "../../../docs/protocol/fast-fee-policy-v1-vectors.json"
    ))
    .unwrap();
    let chain = id(&v, "chain_hex").0;
    let caller = id(&v, "caller_hex").0;
    let raw = hex::decode(v["certificate_hex"].as_str().unwrap()).unwrap();
    let p = FeePolicy::verify_certificate(&raw, chain, caller).unwrap();
    assert_eq!(
        serde_json::to_string(&p).unwrap(),
        v["canonical_terms"].as_str().unwrap()
    );
    assert_eq!(p.owner, id(&v, "owner_hex"));
    assert_eq!(v["native_funding_authority"], false);
    assert!(FeePolicy::verify_certificate(&raw, [0; 32], caller).is_err());
    assert!(FeePolicy::verify_certificate(&raw, chain, [0; 32]).is_err());
    for index in [0, 8, 12, 16, raw.len() - 1] {
        let mut bad = raw.clone();
        bad[index] ^= 1;
        assert!(FeePolicy::verify_certificate(&bad, chain, caller).is_err());
    }
    use ed25519_dalek::{Signer, SigningKey};
    let key = SigningKey::from_bytes(&[171; 32]);
    let canonical = v["canonical_terms"].as_str().unwrap();
    let alternatives = [
        format!("{{ {}", &canonical[1..]),
        format!(
            "{{\"owner\":\"{}\",{}",
            hex::encode(p.owner.0),
            &canonical[1..]
        ),
        format!("{},\"extra\":true}}", &canonical[..canonical.len() - 1]),
        serde_json::to_string(&serde_json::from_str::<Value>(canonical).unwrap()).unwrap(),
    ];
    for terms in alternatives {
        let mut frame = b"RLDFPOL1".to_vec();
        frame.extend([0, 1, 0, 1]);
        frame.extend((terms.len() as u32).to_be_bytes());
        frame.extend(terms.as_bytes());
        frame.extend(
            key.sign(&[b"RLD-FAST-FEE-POLICY-1/CONSENT\0".as_slice(), &frame].concat())
                .to_bytes(),
        );
        assert!(
            FeePolicy::verify_certificate(&frame, chain, caller).is_err(),
            "valid signature cannot permit alternate term encoding"
        );
    }
    let mut trailing = raw;
    trailing.push(0);
    assert!(FeePolicy::verify_certificate(&trailing, chain, caller).is_err());
}
#[test]
fn policy_scope_and_manual_input_paths_refuse_before_missing_key_loading() {
    let mut t = Test::new("scope", 3);
    let policy = t.approve();
    let original = support::out(t.f.channel, 0);
    for damage in 0..5 {
        let mut p = t.plan(4, original.clone(), 0, 120 + damage);
        match damage {
            0 => p.kind = 2,
            1 => p.channel = Id([21; 32]),
            2 => p.inputs = vec![hex::encode(support::out(t.f.channel, 1))],
            3 => p.fee = "2".into(),
            4 => p.expiry = u128::MAX.to_string(),
            _ => unreachable!(),
        }
        let head = t.s.head();
        let request = rid(&mut t.n);
        assert!(t
            .s
            .execute(
                request,
                head,
                Action::FeePolicyPrepare {
                    tip: Id(t.s.tip()),
                    policy_request: policy,
                    plan: p
                },
                None,
                now()
            )
            .is_err());
        assert_eq!(t.s.head(), head);
    }
    let mut bad = t.plan(3, original.clone(), 1, 124);
    let mut certificate = hex::decode(&bad.certificate).unwrap();
    let last = certificate.len() - 1;
    certificate[last] ^= 1;
    bad.certificate = hex::encode(certificate);
    let (_, out) = t.exec(
        Action::FeePolicyPrepare {
            tip: Id(t.s.tip()),
            policy_request: policy,
            plan: bad,
        },
        None,
    );
    assert!(out["diagnostic"].is_string());
    assert!(out["review_digest"].is_null());
    assert!(out["operation_hex"].is_null());
    let p = t.plan(4, original, 0, 125);
    let (prepared, review) = t.prepare(policy, p.clone());
    for (tip, policy_request, review, expected) in [
        (
            Id([1; 32]),
            policy,
            review,
            "INVALID fee policy changed review tip",
        ),
        (
            Id(t.s.tip()),
            policy,
            Id([2; 32]),
            "INVALID persisted native action review",
        ),
        (
            Id(t.s.tip()),
            Id([3; 32]),
            review,
            "INVALID policy signing preparation binding",
        ),
    ] {
        let (_, out) = t.exec(
            Action::FeePolicySign {
                tip,
                policy_request,
                prepare_request: prepared,
                review,
                key_file: t.root.join("missing-stale-scope").to_string_lossy().into(),
            },
            None,
        );
        assert_eq!(out["diagnostic"], expected);
        assert!(out["operation_hex"].is_null());
    }
    assert_eq!(
        t.s.fee_policy_status(t.s.head(), policy, now()).unwrap()["signed_fee_liability"],
        "0"
    );
    let head = t.s.head();
    let request = rid(&mut t.n);
    assert!(t
        .s
        .execute(
            request,
            head,
            Action::OnchainSign {
                tip: Id(t.s.tip()),
                prepare_request: prepared,
                review,
                key_file: t.root.join("missing").to_string_lossy().into(),
                approved: true
            },
            None,
            now()
        )
        .unwrap_err()
        .contains("policy signing"));
    assert_eq!(t.s.head(), head);
    let request = rid(&mut t.n);
    assert!(t
        .s
        .execute(
            request,
            head,
            Action::OnchainPrepare {
                tip: Id(t.s.tip()),
                plan: p
            },
            None,
            now()
        )
        .unwrap_err()
        .contains("fee policy"));
    assert_eq!(t.s.head(), head);
    let mut duplicate = t.terms.clone();
    duplicate.nonce = Id([126; 32]);
    let request = rid(&mut t.n);
    assert!(t
        .s
        .execute(
            request,
            head,
            Action::FeePolicyApprove {
                tip: Id(t.s.tip()),
                terms: duplicate,
                key_file: t.root.join("missing").to_string_lossy().into(),
                approved: true
            },
            None,
            now()
        )
        .unwrap_err()
        .contains("overlapping"));
    assert_eq!(t.s.head(), head);
}
#[test]
fn invalid_owner_consent_funding_expiry_and_limits_never_reach_missing_key() {
    let mut t = Test::new("invalid-consent", 3);
    for damage in 0..12 {
        let clock = now();
        let mut terms = t.terms.clone();
        let mut approved = true;
        match damage {
            0 => terms.chain = Id([1; 32]),
            1 => terms.caller = Id([2; 32]),
            2 => terms.owner = Id(t.f.retainer.verifying_key().to_bytes()),
            3 => {
                terms.total_fee =
                    (t.f.ledger.coins()[&support::out(t.f.channel, 0)].amount + 1).to_string()
            }
            4 => terms.total_fee = "0".into(),
            5 => terms.max_operations = 65,
            6 => terms.expiry_time = (clock - 1).to_string(),
            7 => terms.expiry_height = t.f.ledger.tip().height().to_string(),
            8 => terms.channels.clear(),
            9 => {
                let (input, c) =
                    t.f.ledger
                        .coins()
                        .iter()
                        .find(|(_, c)| c.maturity > t.f.ledger.tip().height() + 1)
                        .unwrap();
                terms.inputs = vec![hex::encode(input)];
                terms.owner = Id(c.owner);
            }
            10 => terms.expiry_time = (clock + 2678401).to_string(),
            11 => approved = false,
            _ => unreachable!(),
        }
        let request = rid(&mut t.n);
        let result = t.s.execute(
            request,
            t.s.head(),
            Action::FeePolicyApprove {
                tip: Id(t.s.tip()),
                terms,
                key_file: t.root.join("missing-never-load").to_string_lossy().into(),
                approved,
            },
            None,
            clock,
        );
        let diagnostic = match result {
            Err(e) => e,
            Ok(v) => v["diagnostic"]
                .as_str()
                .expect("invalid consent cannot sign")
                .to_owned(),
        };
        assert!(
            diagnostic.contains("fee policy"),
            "damage{damage}: {diagnostic}"
        );
        assert!(
            !diagnostic.contains("password"),
            "damage{damage}: {diagnostic}"
        );
    }
    let (_, out) = t.exec(
        Action::FeePolicyApprove {
            tip: Id(t.s.tip()),
            terms: t.terms.clone(),
            key_file: t.key.to_string_lossy().into(),
            approved: true,
        },
        Some(PASSWORD),
    );
    assert!(
        out["diagnostic"].is_null(),
        "failed consents cannot consume a policy slot: {out}"
    );
}
#[test]
fn eight_real_policy_inputs_fit_existing_reply_and_complete_terms_bound_remains_strict() {
    let mut t = Test::new("maximum-inputs", 64);
    let owner = t.terms.owner.0;
    let (input, coin) =
        t.f.ledger
            .coins()
            .iter()
            .find(|(i, c)| {
                c.owner == owner
                    && c.maturity <= t.f.ledger.tip().height() + 1
                    && c.amount > 800
                    && **i != support::out(t.f.channel, 0)
            })
            .unwrap();
    let mut outputs = vec![(owner, 100u128); 7];
    outputs.push((owner, coin.amount - 701));
    let (raw, tx) = support::ordinary(t.f.ledger.chain_id(), &t.f.owners[0], input, &outputs);
    t.include(raw);
    t.terms.inputs = (0..8).map(|i| hex::encode(support::out(tx, i))).collect();
    let policy = t.approve();
    let frame = fs::read(t.node.join("caller.journal")).unwrap();
    assert!(frame.len() < 32 * 1024 * 1024);
    let status = t.s.fee_policy_status(t.s.head(), policy, now()).unwrap();
    assert_eq!(status["remaining_operations"], 64);
    let mut large = t.terms.clone();
    large.channels = (0..8).map(|i| Id([i; 32])).collect();
    large.max_fee = rld_survivor_node::kernel::CAP.to_string();
    large.total_fee = large.max_fee.clone();
    large.expiry_height = u128::MAX.to_string();
    large.expiry_time = u64::MAX.to_string();
    assert!(serde_json::to_vec(&large).unwrap().len() > 1536);
    let request = rid(&mut t.n);
    let head = t.s.head();
    assert!(t
        .s
        .execute(
            request,
            head,
            Action::FeePolicyApprove {
                tip: Id(t.s.tip()),
                terms: large,
                key_file: t.root.join("missing").to_string_lossy().into(),
                approved: true
            },
            None,
            now()
        )
        .unwrap_err()
        .contains("policy terms"));
    assert_eq!(t.s.head(), head);
}
#[test]
fn expiry_blocks_new_signatures_but_never_revokes_or_recharges_existing_proof() {
    // A logical future observation tests policy boundaries, not physical
    // elapsed-time coverage or a product clock override.
    let mut t = Test::new("expiry", 3);
    let owner = t.terms.owner.0;
    let extra =
        t.f.ledger
            .coins()
            .iter()
            .find(|(i, c)| {
                c.owner == owner
                    && c.maturity <= t.f.ledger.tip().height() + 1
                    && **i != support::out(t.f.channel, 0)
            })
            .unwrap()
            .0
            .clone();
    t.terms.inputs.push(hex::encode(&extra));
    t.terms.inputs.sort();
    let policy = t.approve();
    let p = t.plan(4, support::out(t.f.channel, 0), 0, 140);
    let (first, first_review) = t.prepare(policy, p);
    let (_, proof) = t.sign(policy, first, first_review);
    let p = t.plan(3, extra, 1, 141);
    let (second, review) = t.prepare(policy, p);
    let future = t.terms.expiry_time.parse::<u64>().unwrap() + 1;
    let request = rid(&mut t.n);
    let out =
        t.s.execute(
            request,
            t.s.head(),
            Action::FeePolicySign {
                tip: Id(t.s.tip()),
                policy_request: policy,
                prepare_request: second,
                review,
                key_file: t.root.join("missing-expired").to_string_lossy().into(),
            },
            None,
            future,
        )
        .unwrap();
    assert_eq!(out["diagnostic"], "EXPIRED fee policy signing scope");
    assert!(out["operation_hex"].is_null());
    let request = rid(&mut t.n);
    let out =
        t.s.execute(
            request,
            t.s.head(),
            Action::FeePolicySign {
                tip: Id(t.s.tip()),
                policy_request: policy,
                prepare_request: first,
                review: first_review,
                key_file: t.root.join("missing-reproduce").to_string_lossy().into(),
            },
            None,
            future,
        )
        .unwrap();
    assert!(out["diagnostic"].is_null(), "{out}");
    assert_eq!(
        hex::decode(out["operation_hex"].as_str().unwrap()).unwrap(),
        proof
    );
    let status = t.s.fee_policy_status(t.s.head(), policy, future).unwrap();
    assert_eq!(status["signed_fee_liability"], "1");
    assert_eq!(status["policy_time_eligible"], false);
    drop(t.s);
    let mut s = Session::open_controlled(
        &t.node,
        &t.f.genesis,
        t.f.ledger.chain_id(),
        &t.head,
        future,
    )
    .unwrap();
    assert_eq!(
        s.fee_policy_status(s.head(), policy, future).unwrap()["signed_fee_liability"],
        "1"
    );
}
#[test]
fn losing_branch_never_refunds_signed_fee_allowance_or_input_use() {
    let mut t = Test::new("reorg", 2);
    let policy = t.approve();
    let mut fork = t.f.ledger.clone();
    t.two_claims(policy);
    let miner = t.f.miner.verifying_key().to_bytes();
    for _ in 0..4 {
        let raw = support::mine_until(&mut fork, miner, vec![], t.f.now, t.deadline);
        let (_, out) = t.exec(
            Action::Native {
                tip: Id(t.s.tip()),
                block: hex::encode(raw),
            },
            None,
        );
        assert!(out["diagnostic"].is_null());
    }
    assert_eq!(t.s.tip(), fork.tip().id());
    assert!(fork.coins().contains_key(&support::out(t.f.channel, 0)));
    let status = t.s.fee_policy_status(t.s.head(), policy, now()).unwrap();
    assert_eq!(status["signed_fee_liability"], "2");
    assert_eq!(status["remaining_operations"], 0);
    // Keep the earlier complete reserved intent (including nonce/certificate)
    // so this reaches allowance validation instead of the independent conflict
    // guard that correctly refuses a changed intent against reserved inputs.
    let p = t.plan(4, support::out(t.f.channel, 0), 0, 115);
    let request = rid(&mut t.n);
    let head = t.s.head();
    assert!(t
        .s
        .execute(
            request,
            head,
            Action::FeePolicyPrepare {
                tip: Id(t.s.tip()),
                policy_request: policy,
                plan: p
            },
            None,
            now()
        )
        .unwrap_err()
        .contains("allowance exhausted"));
    assert_eq!(t.s.head(), head);
}
#[test]
fn fee_policy_cut_child() {
    let Some(path) = std::env::var_os("RLD_FEE_POLICY_CUT") else {
        return;
    };
    let v: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let root = PathBuf::from(v["root"].as_str().unwrap());
    let g = fs::read(root.join("genesis")).unwrap();
    let chain = fast::genesis_id(&g);
    let mut s =
        Session::open_controlled(&root.join("session"), &g, chain, &root.join("head"), now())
            .unwrap();
    let action: Action = serde_json::from_value(v["action"].clone()).unwrap();
    let request = id(&v, "request");
    let cut = v["cut"].as_str().unwrap();
    s.execute_observed(request, s.head(), action, Some(PASSWORD), now(), |b| {
        use rld_survivor_node::fast_session::Boundary;
        let at = match b {
            Boundary::IntentDurable => "intent",
            Boundary::NativeActionEvaluated => "evaluated",
            Boundary::ReplyDurable => "reply",
            Boundary::ChildDurable => "child",
        };
        if at == cut {
            write(&root.join("marker"), at.as_bytes());
            let deadline = Instant::now() + Duration::from_secs(180);
            loop {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    })
    .unwrap();
    panic!("missing requested fee policy process boundary");
}
struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[test]
fn actual_policy_consent_and_fee_signature_cuts_recover_without_keys_or_first_signatures() {
    use std::process::{Command, Stdio};
    let deadline = Instant::now() + Duration::from_secs(180);
    for mode in ["consent", "fee"] {
        for cut in ["intent", "evaluated", "reply"] {
            let mut t = Test::new(&format!("cut-{mode}-{cut}"), 3);
            let mut policy = None;
            let action = if mode == "consent" {
                Action::FeePolicyApprove {
                    tip: Id(t.s.tip()),
                    terms: t.terms.clone(),
                    key_file: t.key.to_string_lossy().into(),
                    approved: true,
                }
            } else {
                let p = t.approve();
                policy = Some(p);
                let plan = t.plan(4, support::out(t.f.channel, 0), 0, 130);
                let (prepare, review) = t.prepare(p, plan);
                Action::FeePolicySign {
                    tip: Id(t.s.tip()),
                    policy_request: p,
                    prepare_request: prepare,
                    review,
                    key_file: t.key.to_string_lossy().into(),
                }
            };
            let request = rid(&mut t.n);
            drop(t.s);
            let config = t.root.join("cut.json");
            write(
                &config,
                json!({"root":t.root,"action":action,"request":request,"cut":cut})
                    .to_string()
                    .as_bytes(),
            );
            let mut child = Child(
                Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "fee_policy_cut_child", "--nocapture"])
                    .env("RLD_FEE_POLICY_CUT", config)
                    .stdin(Stdio::null())
                    .stdout(fs::File::create(t.root.join("stdout.log")).unwrap())
                    .stderr(fs::File::create(t.root.join("stderr.log")).unwrap())
                    .spawn()
                    .unwrap(),
            );
            while !t.root.join("marker").exists() {
                assert!(Instant::now() < deadline, "original180 policy/fee cuts");
                assert!(child.0.try_wait().unwrap().is_none());
                std::thread::sleep(Duration::from_millis(10));
            }
            child.0.kill().unwrap();
            let status = child.0.wait().unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(status.signal(), Some(9));
            }
            fs::rename(&t.key, t.root.join("retained-fee.key")).unwrap();
            let native = fs::read(t.node.join("native.journal")).unwrap();
            let (mut s, out) = Session::recover_controlled(
                &t.node,
                &t.f.genesis,
                t.f.ledger.chain_id(),
                &t.head,
                now(),
            )
            .unwrap();
            assert_eq!(out["recovery_key_loaded"], false);
            assert_eq!(
                out["operation_hex"].is_string(),
                mode == "fee" && cut == "reply"
            );
            assert_eq!(
                out["fee_policy"]["policy_hex"].is_string(),
                mode == "consent" && cut == "reply"
            );
            assert_eq!(fs::read(t.node.join("native.journal")).unwrap(), native);
            if let Some(policy) = policy {
                assert_eq!(
                    s.fee_policy_status(s.head(), policy, now()).unwrap()["signed_fee_liability"],
                    if cut == "reply" { "1" } else { "0" }
                );
            }
            assert!(Instant::now() < deadline);
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Reply {
    id: Id,
    request: Id,
    effect: Option<Id>,
    review: Option<Id>,
    diagnostic: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization: Option<String>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Intent {
    id: Id,
    action: Action,
    at: u64,
}
fn hash(label: &str, raw: &[u8]) -> Hash {
    use sha2::{Digest, Sha256};
    Sha256::digest(
        [
            b"RLD-FAST-SESSION-1/".as_slice(),
            label.as_bytes(),
            &[0],
            raw,
        ]
        .concat(),
    )
    .into()
}
fn change_caller(node: &Path, head: &Path, target: Id, purpose: bool) {
    let path = node.join("caller.journal");
    let old = fs::read(&path).unwrap();
    let mut next = old[..229].to_vec();
    let mut prior = hash("HEADER", &next);
    let mut at = 229;
    let mut replacement = None;
    while at < old.len() {
        let n = u32::from_be_bytes(old[at..at + 4].try_into().unwrap()) as usize;
        let b = &old[at + 4..at + 4 + n];
        at += 4 + n;
        let size = u32::from_be_bytes(b[33..37].try_into().unwrap()) as usize;
        let mut payload = b[37..37 + size].to_vec();
        if b[0] == 1 && purpose {
            let mut i: Intent = serde_json::from_slice(&payload).unwrap();
            if i.id == target {
                let Action::FeePolicySign {
                    tip,
                    prepare_request,
                    review,
                    key_file,
                    ..
                } = i.action
                else {
                    panic!("expected policy fee signing intent");
                };
                i.action = Action::OnchainSign {
                    tip,
                    prepare_request,
                    review,
                    key_file,
                    approved: true,
                };
                replacement = Some(i.action.digest().unwrap());
                payload = serde_json::to_vec(&i).unwrap();
            }
        } else if b[0] == 2 {
            let mut d: Reply = serde_json::from_slice(&payload).unwrap();
            if d.id == target {
                if purpose {
                    d.request = replacement.unwrap();
                } else {
                    let mut raw = hex::decode(d.authorization.as_ref().unwrap()).unwrap();
                    let n = raw.len();
                    raw[n - 1] ^= 1;
                    d.authorization = Some(hex::encode(raw));
                }
                payload = serde_json::to_vec(&d).unwrap();
            }
        }
        let mut record = vec![b[0]];
        record.extend(prior);
        record.extend((payload.len() as u32).to_be_bytes());
        record.extend(payload);
        prior = hash("RECORD", &record);
        record.extend(prior);
        next.extend((record.len() as u32).to_be_bytes());
        next.extend(record);
    }
    fs::write(&path, next).unwrap();
    let mut control = fs::read(head).unwrap();
    assert_eq!(&control[108..112], &[0; 4]);
    control[76..108].copy_from_slice(&prior);
    let n = control.len();
    let digest = hash("CONTROL", &control[..n - 32]);
    control[n - 32..].copy_from_slice(&digest);
    fs::write(head, control).unwrap();
}
#[test]
fn rehashed_policy_or_fee_signatures_and_fabricated_boolean_consent_refuse_unchanged() {
    for mode in 0..3 {
        let mut t = Test::new(&format!("rehash-{mode}"), 3);
        let policy = t.approve();
        let plan = t.plan(4, support::out(t.f.channel, 0), 0, 131);
        let (prepare, review) = t.prepare(policy, plan);
        let (signed, _) = t.sign(policy, prepare, review);
        drop(t.s);
        change_caller(
            &t.node,
            &t.head,
            if mode == 0 { policy } else { signed },
            mode == 2,
        );
        let caller = fs::read(t.node.join("caller.journal")).unwrap();
        let native = fs::read(t.node.join("native.journal")).unwrap();
        let control = fs::read(&t.head).unwrap();
        assert!(
            Session::open_controlled(&t.node, &t.f.genesis, t.f.ledger.chain_id(), &t.head, now())
                .is_err(),
            "mode{mode}"
        );
        assert_eq!(fs::read(t.node.join("caller.journal")).unwrap(), caller);
        assert_eq!(fs::read(t.node.join("native.journal")).unwrap(), native);
        assert_eq!(fs::read(&t.head).unwrap(), control);
    }
}

#[test]
fn cold_policy_preparation_still_checks_original_time_against_signed_owner_expiry() {
    let mut t = Test::new("rehashed-preparation-expiry", 3);
    let policy = t.approve();
    let plan = t.plan(4, support::out(t.f.channel, 0), 0, 151);
    let (prepared, _) = t.prepare(policy, plan);
    let future = t.terms.expiry_time.parse::<u64>().unwrap() + 1;
    drop(t.s);
    let path = t.node.join("caller.journal");
    let old = fs::read(&path).unwrap();
    let mut next = old[..229].to_vec();
    let mut prior = hash("HEADER", &next);
    let mut at = 229;
    let mut changed = false;
    while at < old.len() {
        let n = u32::from_be_bytes(old[at..at + 4].try_into().unwrap()) as usize;
        let b = &old[at + 4..at + 4 + n];
        at += 4 + n;
        let size = u32::from_be_bytes(b[33..37].try_into().unwrap()) as usize;
        let mut payload = b[37..37 + size].to_vec();
        if b[0] == 1 {
            let mut i: Intent = serde_json::from_slice(&payload).unwrap();
            if i.id == prepared {
                i.at = future;
                payload = serde_json::to_vec(&i).unwrap();
                changed = true;
            }
        }
        let mut record = vec![b[0]];
        record.extend(prior);
        record.extend((payload.len() as u32).to_be_bytes());
        record.extend(payload);
        prior = hash("RECORD", &record);
        record.extend(prior);
        next.extend((record.len() as u32).to_be_bytes());
        next.extend(record);
    }
    assert!(changed);
    fs::write(&path, &next).unwrap();
    let mut control = fs::read(&t.head).unwrap();
    control[76..108].copy_from_slice(&prior);
    let n = control.len();
    let digest = hash("CONTROL", &control[..n - 32]);
    control[n - 32..].copy_from_slice(&digest);
    fs::write(&t.head, &control).unwrap();
    let native = fs::read(t.node.join("native.journal")).unwrap();
    let e = Session::open_controlled(
        &t.node,
        &t.f.genesis,
        t.f.ledger.chain_id(),
        &t.head,
        future,
    )
    .err()
    .expect("expired original policy preparation must refuse");
    assert!(e.contains("EXPIRED fee policy signing scope"), "{e}");
    assert_eq!(fs::read(&path).unwrap(), next);
    assert_eq!(fs::read(&t.head).unwrap(), control);
    assert_eq!(fs::read(t.node.join("native.journal")).unwrap(), native);
}
