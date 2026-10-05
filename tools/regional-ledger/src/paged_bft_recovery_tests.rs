use super::retained_native_replay::inventory;
use super::*;

pub(super) fn copy_private(source: &Path, target: &Path) {
    fs::create_dir(target).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(target, fs::Permissions::from_mode(0o700)).unwrap();
    }
    for entry in fs::read_dir(source).unwrap() {
        let path = entry.unwrap().path();
        let to = target.join(path.file_name().unwrap());
        if path.is_dir() {
            copy_private(&path, &to);
        } else {
            crate::keystore::private_create(&to, &fs::read(path).unwrap()).unwrap();
        }
    }
}
fn json(path: &Path) -> serde_json::Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

#[test]
fn paged_exact_pending_response_recovery_preserves_full_native_prepare_lock_and_refuses_new_signing(
) {
    let started = std::time::Instant::now();
    for boundary in 0..3 {
        let mut h = Harness::with_rules(crate::paged_bft::RULES);
        h.retain = true;
        let p = h.proposal(0, None, h.node.bft_candidate(vec![], public(10)).unwrap());
        let q = h.prepare(&p, &[0, 1, 2, 3]);
        // Real commit creates an actual durable prepare-QC lock in each signer.
        h.commit(&p, &q, &[0, 1, 2, 3]);
        let context = Context::current(&h.node).unwrap();
        let mut round = 0;
        while h.agents[0].record_count() < 15 {
            h.sign(
                0,
                Request::Timeout {
                    context: context.clone(),
                    round,
                },
            );
            round += 1;
        }
        let previous = h.heads[0];
        crate::keystore::private_create(&h.root.join("caller-pending.head"), &previous.0).unwrap();
        let request = Request::Timeout {
            context: context.clone(),
            round,
        };
        h.agents[0].interrupt_publication(boundary);
        assert!(h.agents[0]
            .sign(
                &h.node,
                request.clone(),
                Some(&h.root.join(format!("key-{}.json", h.seeds[0]))),
                previous
            )
            .is_err());
        let dir = h.root.join(format!("signer-{}", h.seeds[0]));
        let pending = dir.join("bft-records/stream.next");
        let publication = json(&pending);
        assert_eq!(publication["manifest"]["count"], 16);
        assert_eq!(publication["pages"].as_array().unwrap().len(), 1);
        let exact: bft::Record =
            serde_json::from_value(publication["pages"][0]["records"][15].clone()).unwrap();
        assert_eq!(exact.request, request);
        assert_eq!(exact.previous_head, previous);
        let Message::Timeout(timeout) = &exact.message else {
            panic!("retained response must be timeout");
        };
        assert_eq!(timeout.high.as_ref(), Some(&q));
        let proposed: Hash =
            serde_json::from_value(publication["manifest"]["head"].clone()).unwrap();
        // Failure retains complete already-signed bytes. Original native/caller
        // head cannot advance just because proposed manifest already published.
        assert_eq!(
            fs::read(h.root.join("caller-pending.head")).unwrap(),
            previous.0
        );
        h.agents.clear();
        assert!(Agent::open(&dir, &h.node).is_err());
        let before = inventory(&h.root);
        let wrong = Request::Timeout {
            context: context.clone(),
            round: round + 1,
        };
        assert!(Agent::recover_response(&dir, &h.node, wrong.clone(), previous).is_err());
        assert!(Agent::recover_response(&dir, &h.node, request.clone(), Hash([8; 32])).is_err());
        assert!(Agent::recover_response(
            &h.root.join("missing-custody"),
            &h.node,
            request.clone(),
            previous
        )
        .is_err());
        assert_eq!(inventory(&h.root), before);
        // Bad signature remains storage-hash-consistent: alter only its last
        // retained response and recompute every related complete wrapper digest.
        let bad = h.root.join("bad-retained-signature");
        copy_private(&dir, &bad);
        crate::retained_pages::rewrite_last_pending_for_fixture::<bft::Record>(
            &bad.join("bft-records"),
            |record| {
                let Message::Timeout(timeout) = &mut record.message else {
                    panic!("last native message");
                };
                timeout.approval.signature = "00".repeat(64);
            },
        );
        let bad_before = inventory(&h.root);
        let error = Agent::recover_response(&bad, &h.node, request.clone(), previous).unwrap_err();
        assert!(
            error.contains("signature"),
            "hash-consistent attack must reach native signature authentication: {error}"
        );
        assert_eq!(inventory(&h.root), bad_before);
        let recovered = Agent::recover_response(&dir, &h.node, request.clone(), previous).unwrap();
        assert!(recovered.recovered_exact_retry);
        assert_eq!(recovered.message, exact.message);
        assert_eq!(recovered.previous_head, previous);
        assert_eq!(recovered.head, proposed);
        let (agent, status) = Agent::open_with_status(&dir, &h.node).unwrap();
        assert_eq!(agent.record_count(), 16);
        assert_eq!(agent.head().unwrap(), proposed);
        let status = serde_json::to_value(status).unwrap();
        assert_eq!(status["state"]["lock"], serde_json::to_value(&q).unwrap());
        assert_eq!(status["state"]["round"], round + 1);
        drop(agent);
        assert!(!pending.exists());
        let stable = inventory(&h.root);
        assert!(Agent::recover_response(&dir, &h.node, wrong, proposed).is_err());
        assert_eq!(inventory(&h.root), stable);
        assert_eq!(
            Agent::recover_response(&dir, &h.node, request, previous)
                .unwrap()
                .message,
            exact.message
        );
        assert_eq!(inventory(&h.root), stable);
        println!("paged-recovery boundary={boundary} complete_page=true records=16 prepare_lock_preserved=true original_response_equal=true new_signing=false actual_sigkill=false");
    }
    println!(
        "paged-recovery finite_component_complete elapsed={:.3}",
        started.elapsed().as_secs_f64()
    );
}
