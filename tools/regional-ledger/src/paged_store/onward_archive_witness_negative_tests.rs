//! Fresh archive-read refusals, not Runtime consensus or owner qualification.
//! All defective archives are separate retained inputs; the Native target is
//! initialized only by ordinary complete proof/certificate verification.
use super::negative_seams::{authentic_alternate_a80, Target};
use super::queue_negative::authentic_wrapper_variant;
use super::*;
use crate::bft::{Context, Request};
use crate::bft_onward_network::execution_cost;
use crate::bft_runtime_archive::{Archive, Client, Header as EnvelopeHeader};
use crate::bft_runtime_envelope::Wire;

const MISSING: &str = "onward cold complete material absent from Native history";
fn check(deadline: f64) {
    assert!(
        now() < deadline,
        "original 60-second archive witness negatives exhausted"
    );
}
fn measured<T>(
    rows: &mut Vec<Value>,
    label: &str,
    expected: (u64, u64),
    call: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let scope = execution_cost::Scope::begin();
    let result = call();
    let cost = scope.finish();
    assert!(cost.complete, "{label}");
    assert_eq!(cost.calls, cost.successful + cost.failed, "{label}");
    assert_eq!(cost.calls, cost.verification_calls, "{label}");
    assert_eq!((cost.calls, cost.failed), expected, "{label}");
    assert_eq!(cost.max_depth, u64::from(cost.calls > 0), "{label}");
    assert!(cost.verification_seconds.is_finite() && cost.verification_seconds >= 0.0);
    assert!(rows.len() < 24);
    rows.push(
        json!({"label":label,"expected_calls":expected.0,"expected_failed":expected.1,
        "calls":cost.calls,"pure":cost.verification_calls,"successful":cost.successful,
        "failed":cost.failed,"max_depth":cost.max_depth,"complete":cost.complete,
        "accepted":result.is_ok(),"error":result.as_ref().err(),"execution":cost}),
    );
    result
}
fn expanded(archive: &Archive, ident: Hash) -> net::Envelope {
    let wire: net::WireEnvelope =
        serde_json::from_value(archive.envelope(&archive.runtime.messages[&ident]).unwrap())
            .unwrap();
    wire.expand().unwrap()
}
fn wire(envelope: &net::Envelope) -> Wire {
    Wire::decode(
        serde_json::to_value(envelope.pack().unwrap()).unwrap(),
        bft_client::ONWARD_FORMAT,
    )
    .unwrap()
}
fn shared(archive: &mut Archive, value: Value) -> Hash {
    let reference = sha(&files::canonical(&value).unwrap());
    if let Some(old) = archive.snapshots.insert(reference, value.clone()) {
        assert_eq!(old, value);
    }
    reference
}
// Complete C1 graph reconstruction is fixture-only. Unlike the C0 helper, this
// retains every ordered carried evidence reference and the full wrapper.
fn repack(base: &Archive, replacements: &BTreeMap<Hash, net::Envelope>) -> Archive {
    let mut archive = base.clone();
    archive.runtime.messages.clear();
    archive.snapshots.clear();
    for (ident, previous) in &base.runtime.messages {
        let envelope = replacements
            .get(ident)
            .cloned()
            .unwrap_or_else(|| expanded(base, *ident));
        let packed = envelope.pack().unwrap();
        let value = serde_json::to_value(&packed).unwrap();
        let raw = files::canonical_with_limit(&value, crate::contact::MAX_PAYLOAD).unwrap();
        let mut record = previous.clone();
        record.header = EnvelopeHeader {
            format: packed.format,
            currency: packed.currency,
            region: packed.region,
        };
        record.body = value["body"].clone();
        record.sha256 = sha(&raw);
        record.size_bytes = raw.len();
        record.value = envelope.body.checkpoint_value().unwrap();
        record.origin_refs = None;
        record.refs = value["evidence"]["snapshots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| shared(&mut archive, v.clone()))
            .collect();
        record.onward_history_ref = if value["history"].is_null() {
            None
        } else {
            Some(shared(&mut archive, value["history"].clone()))
        };
        let body_id = sha(&files::canonical(&record.body).unwrap());
        assert!(archive.runtime.messages.insert(body_id, record).is_none());
    }
    let raw = files::canonical_with_limit(&archive, crate::bft_runtime_archive::MAX_STATE).unwrap();
    assert_eq!(Archive::decode(&raw).unwrap(), archive);
    archive
}
struct Reads<'a> {
    root: &'a Path,
    node: &'a Store,
    key: String,
}
impl Reads<'_> {
    fn client(&self, label: &str, archive: &Archive, graph_valid: bool) -> Client {
        let path = dir(&self.root.join(label));
        let raw =
            files::canonical_with_limit(archive, crate::bft_runtime_archive::MAX_STATE).unwrap();
        assert_eq!(Archive::decode(&raw).is_ok(), graph_valid);
        crate::keystore::private_create(&path.join("state.json"), &raw).unwrap();
        // All input/lock preparation precedes the nonmutation inventory.
        Client::lock(
            &path,
            self.key.clone(),
            bft_client::ONWARD_FORMAT.into(),
            self.node,
        )
        .unwrap()
    }
    fn unchanged<T>(&self, call: impl FnOnce() -> T) -> T {
        let before = inventory(self.root);
        let head = self.node.storage_head().unwrap();
        let ledger = self.node.chain.ledger.clone();
        let result = call();
        assert_eq!(self.node.storage_head().unwrap(), head);
        assert_eq!(self.node.chain.ledger, ledger);
        assert_eq!(
            inventory(self.root),
            before,
            "reader changed original Native/caller/archive files"
        );
        result
    }
    fn refuse(
        &self,
        rows: &mut Vec<Value>,
        label: &str,
        archive: &Archive,
        expected: (u64, u64, &str),
    ) {
        let client = self.client(label, archive, true);
        self.unchanged(|| {
            let error = measured(rows, label, (expected.0, expected.1), || {
                client.read_authenticated(self.node)
            })
            .unwrap_err();
            assert!(
                error.contains(expected.2),
                "{label}: expected {:?}, got {error:?}",
                expected.2
            );
        });
    }
}
fn alternate_certificate(original: &Snapshot) -> Snapshot {
    let mut alternate = original.clone();
    let certificate = alternate.bft.as_mut().unwrap();
    for quorum in [&mut certificate.prepared, &mut certificate.committed] {
        let seed = (2u8..6)
            .find(|seed| {
                !quorum
                    .votes
                    .iter()
                    .any(|vote| vote.approval.key == public(*seed))
            })
            .unwrap();
        let mut vote = quorum.votes[2].clone();
        vote.approval.key = public(seed);
        vote.approval.signature = signature(seed, &vote.bytes().unwrap());
        quorum.votes[2] = vote;
        quorum
            .votes
            .sort_by(|a, b| a.approval.key.cmp(&b.approval.key));
    }
    assert_ne!(&alternate, original);
    assert_eq!(alternate.statement, original.statement);
    alternate
}

#[test]
#[ignore = "one fresh 60-second complete archive witness refusal component"]
fn onward_archive_witness_refuses_late_authority_and_uninstalled_material() {
    let started = now();
    let deadline = started + 60.0;
    let (root, bootstrap, proof, _, _, _) = ancestors();
    check(deadline);
    let mut target = Target::new(
        &root,
        "archive-negative-target",
        &bootstrap,
        proof.history.destination,
    );
    let c1 = certified_with_commands(&target.node.paged_replay.as_ref().unwrap().replay, vec![]);
    target.node.finalize(c1.clone()).unwrap();
    target
        .node
        .accept_complete_onward_network_history(proof.clone())
        .unwrap();
    let native_head = target.node.storage_head().unwrap();
    for round in 0..4 {
        check(deadline);
        let message = target
            .actor
            .as_mut()
            .unwrap()
            .sign_fixture_control(
                &target.node,
                Request::Timeout {
                    context: Context::current(&target.node).unwrap(),
                    round,
                },
            )
            .unwrap();
        assert!(
            matches!(message, Message::Timeout(ref vote) if vote.round==round && vote.context.parent_height==1)
        );
    }
    let finalized = net::Envelope {
        format: net::FORMAT.into(),
        currency: target.node.trust.currency().unwrap(),
        region: target.node.chain.region,
        history: Some(proof.clone()),
        evidence: Evidence {
            snapshots: vec![c1.clone()],
        },
        body: Body::Finalized(Box::new(c1.clone())),
    };
    target
        .actor
        .as_mut()
        .unwrap()
        .receive(&mut target.node, &strict_frame(finalized))
        .unwrap();
    assert_eq!(target.node.storage_head().unwrap(), native_head);
    target.stop();
    let raw = fs::read(target.root.join("runtime-0/state.json")).unwrap();
    let base = Archive::decode(&raw).unwrap();
    assert_eq!(base.runtime.messages.len(), 5);
    let ids = base.runtime.messages.keys().copied().collect::<Vec<_>>();
    let first = ids[0];
    let last = ids[4];
    for ident in &ids {
        let envelope = expanded(&base, *ident);
        assert_eq!(envelope.history.as_ref(), Some(&proof));
        assert_eq!(envelope.evidence.snapshots, vec![c1.clone()]);
    }
    let timeout = *ids
        .iter()
        .rev()
        .find(|ident| {
            matches!(expanded(&base, **ident).body,
        Body::Signed(ref message) if matches!(message.as_ref(), Message::Timeout(_)))
        })
        .unwrap();
    assert_ne!(timeout, first);
    let key = base.runtime.binding.key.clone();
    let mut rows = Vec::new();
    let reads = Reads {
        root: &root,
        node: &target.node,
        key: key.clone(),
    };
    let original = reads.client("original-five", &base, true);
    reads.unchanged(|| {
        let a = measured(&mut rows, "actual-read-first", (1, 0), || {
            original.read_authenticated(&target.node)
        })
        .unwrap();
        let b = measured(&mut rows, "actual-read-independent", (1, 0), || {
            original.read_authenticated(&target.node)
        })
        .unwrap();
        let c = measured(&mut rows, "actual-read-cap-zero", (5, 0), || {
            original.read_authenticated_with_limit_for_test(&target.node, 0)
        })
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.0, base);
        assert_eq!(a.1, sha(&raw));
        assert_eq!(
            measured(&mut rows, "independent-wire-cold", (1, 0), || wire(
                &expanded(&base, first)
            )
            .verify_cold(&target.node))
            .unwrap(),
            base.runtime.messages[&first].value
        );
    });
    check(deadline);

    let mut bad_body = expanded(&base, timeout);
    let mut found = false;
    for byte in 0u8..=u8::MAX {
        let Body::Signed(message) = &mut bad_body.body else {
            panic!("actual signed Timeout")
        };
        let Message::Timeout(vote) = message.as_mut() else {
            panic!("actual Timeout")
        };
        let mut invalid = [0u8; 64];
        invalid[0] = byte;
        vote.approval.signature = hex::encode(invalid);
        if sha(&files::canonical(&serde_json::to_value(&bad_body.body).unwrap()).unwrap()) > first {
            found = true;
            break;
        }
    }
    assert!(
        found,
        "bounded invalid-signature identity search found no later record"
    );
    let expected = bad_body.verify(&target.node).unwrap_err();
    let changed = repack(&base, &BTreeMap::from([(timeout, bad_body)]));
    assert_eq!(
        *changed.runtime.messages.first_key_value().unwrap().0,
        first
    );
    reads.refuse(
        &mut rows,
        "late-body-signature",
        &changed,
        (1, 0, &expected),
    );

    let mut bad_c = expanded(&base, last);
    bad_c.evidence.snapshots[0]
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    let expected = bad_c.verify(&target.node).unwrap_err();
    reads.refuse(
        &mut rows,
        "late-c-certificate",
        &repack(&base, &BTreeMap::from([(last, bad_c)])),
        (1, 0, &expected),
    );
    let mut bad_foreign = expanded(&base, last);
    bad_foreign.history.as_mut().unwrap().history.snapshots[3]
        .bft
        .as_mut()
        .unwrap()
        .committed
        .votes[0]
        .approval
        .signature = "00".repeat(64);
    let expected = bad_foreign.verify(&target.node).unwrap_err();
    reads.refuse(
        &mut rows,
        "late-foreign-signature",
        &repack(&base, &BTreeMap::from([(last, bad_foreign)])),
        (2, 1, &expected),
    );
    let mut bad_value = base.clone();
    let value = &mut bad_value.runtime.messages.get_mut(&last).unwrap().value;
    *value = if value.is_some() {
        None
    } else {
        Some(Hash::ZERO)
    };
    reads.refuse(
        &mut rows,
        "late-record-value",
        &bad_value,
        (
            1,
            0,
            "BFT cold archive value differs from complete Native envelope",
        ),
    );
    check(deadline);

    let alternate = authentic_wrapper_variant(&proof);
    let mut alternate_envelope = expanded(&base, ids[1]);
    alternate_envelope.history = Some(alternate.clone());
    alternate_envelope.verify(&target.node).unwrap();
    assert_eq!(
        wire(&alternate_envelope)
            .verify_cold(&target.node)
            .unwrap_err(),
        MISSING
    );
    let two_qcs = repack(&base, &BTreeMap::from([(ids[1], alternate_envelope)]));
    reads.refuse(
        &mut rows,
        "valid-uninstalled-wrapper",
        &two_qcs,
        (2, 0, MISSING),
    );
    let mut alternate_c = expanded(&base, timeout);
    alternate_c.evidence.snapshots = vec![alternate_certificate(&c1)];
    alternate_c.verify(&target.node).unwrap();
    assert_eq!(
        wire(&alternate_c).verify_cold(&target.node).unwrap_err(),
        MISSING
    );
    reads.refuse(
        &mut rows,
        "valid-uninstalled-c",
        &repack(&base, &BTreeMap::from([(timeout, alternate_c)])),
        (1, 0, MISSING),
    );

    let mut wrong_domain = expanded(&base, last);
    wrong_domain.currency = Hash::ZERO;
    reads.refuse(
        &mut rows,
        "wrong-currency-domain",
        &repack(&base, &BTreeMap::from([(last, wrong_domain)])),
        (0, 0, "BFT archive retained envelope domain differs"),
    );
    let old_profile_path = dir(&root.join("wrong-old-profile"));
    reads.unchanged(|| {
        let error = measured(&mut rows, "wrong-old-profile", (0, 0), || {
            Client::lock(
                &old_profile_path,
                key.clone(),
                bft_client::FORMAT.into(),
                &target.node,
            )
            .map(|_| ())
        })
        .unwrap_err();
        assert_eq!(
            error,
            "complete onward network requires separately integrated ordinary runtime"
        );
    });
    let mut broken = base.clone();
    broken.runtime.messages.get_mut(&last).unwrap().refs[0] = Hash::ZERO;
    let graph = reads.client("broken-late-graph", &broken, false);
    reads.unchanged(|| {
        assert_eq!(
            measured(&mut rows, "broken-late-graph", (0, 0), || graph
                .read_authenticated(&target.node))
            .unwrap_err(),
            "BFT archive shared snapshot missing"
        );
    });
    // None remains a valid empty foreign context for a genuine local Timeout.
    let mut no_history = expanded(&base, timeout);
    no_history.history = None;
    no_history.verify(&target.node).unwrap();
    let none_archive = repack(&base, &BTreeMap::from([(timeout, no_history)]));
    let none_client = reads.client("valid-history-none-timeout", &none_archive, true);
    reads.unchanged(|| {
        assert_eq!(
            measured(&mut rows, "valid-history-none-timeout", (1, 0), || {
                none_client.read_authenticated(&target.node)
            })
            .unwrap()
            .0,
            none_archive
        );
    });
    check(deadline);

    // The refused archive is retained. This new Native operation installs the
    // genuine alternate certificate; a new archive then exercises A,B,A,A,A.
    target
        .node
        .accept_complete_onward_network_history(alternate)
        .unwrap();
    assert_ne!(target.node.storage_head().unwrap(), native_head);
    assert_eq!(target.node.chain.ledger, Ledger::default());
    let reads = Reads {
        root: &root,
        node: &target.node,
        key: key.clone(),
    };
    let installed = reads.client("installed-two-qcs", &two_qcs, true);
    reads.unchanged(|| {
        let expected = sha(&files::canonical_with_limit(
            &two_qcs,
            crate::bft_runtime_archive::MAX_STATE,
        )
        .unwrap());
        let a = measured(&mut rows, "installed-qc-first-entry", (2, 0), || {
            installed.read_authenticated(&target.node)
        })
        .unwrap();
        let b = measured(&mut rows, "installed-qc-cap-zero", (5, 0), || {
            installed.read_authenticated_with_limit_for_test(&target.node, 0)
        })
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.0, two_qcs);
        assert_eq!(a.1, expected);
    });
    // Hold the real Client across a later genuine incident, never a witness.
    let incident_client = reads.client("known-incident", &base, true);
    reads.unchanged(|| {
        assert_eq!(
            measured(&mut rows, "pre-incident-independent-read", (1, 0), || {
                incident_client.read_authenticated(&target.node)
            })
            .unwrap()
            .0,
            base
        );
    });
    let alternate_a = authentic_alternate_a80(&bootstrap, &proof);
    let conflict =
        Conflict::from_snapshots(&proof.history.origin.snapshots[79], &alternate_a).unwrap();
    target.node.observe_conflict(conflict).unwrap();
    assert_eq!(target.node.journal.incident_ids.len(), 1);
    let reads = Reads {
        root: &root,
        node: &target.node,
        key,
    };
    reads.unchanged(|| {
        let error = measured(&mut rows, "known-incident-refusal", (0, 0), || {
            incident_client.read_authenticated(&target.node)
        })
        .unwrap_err();
        assert!(error.contains("operations are quarantined"), "{error}");
    });
    check(deadline);
    assert_eq!(rows.len(), 18);
    eprintln!(
        "onward_archive_witness_negative_result={}",
        json!({
            "root":root,"passed":true,"elapsed_seconds":now()-started,"controls":rows.len(),"rows":rows,
            "actual_original_c0_agent":true,"c1_certificate_fixture":true,"archive_records":5,
            "independent_read_scope":true,"late_body_refused":true,"late_c_certificate_refused":true,
            "late_foreign_signature_refused":true,"late_value_refused":true,
            "valid_uninstalled_wrapper_refused":true,"valid_uninstalled_c_refused":true,
            "installed_qc_first_entry_preserved":true,"cap_zero_full":true,
            "domain_and_graph_refused":true,"valid_none_history_timeout":true,
            "known_incident_refused":true,"all_refusals_unchanged":true,
            "same_call_incident_simulated":false,"changed_signed_trust_fixture":false,
            "fresh_process_cold":false,"ordinary_service":false,"owner_payment_qualified":false,
            "independent_qualification":false
        })
    );
}
