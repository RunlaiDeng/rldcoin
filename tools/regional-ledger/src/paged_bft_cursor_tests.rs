use super::paged_integration::certify;
use super::retained_native_replay::inventory;
use super::*;
use std::cell::RefCell;
#[test]
fn paged_local_cursor_rechecks_later_native_bytes_guard_and_new_signature() {
    for attack in 0..=5 {
        let mut h = Harness::with_rules(crate::paged_bft::RULES);
        h.retain = true;
        // The shared certification helper reads separately retained caller heads.
        for n in 0..4 {
            super::paged_integration::retain(&h.root, n, h.heads[n]);
        }
        for _ in 0..2 {
            let snapshot = certify(&mut h, vec![]);
            h.node.finalize(snapshot).unwrap();
        }
        let request = Request::Timeout {
            context: Context::current(&h.node).unwrap(),
            round: 0,
        };
        let before = inventory(&h.root);
        let after_attack = RefCell::new(None);
        let mutate = || {
            let (path, raw) = match attack {
                2 | 3 => (h.root.join("node/INCIDENT_GUARD"), Hash([7; 32]).0.to_vec()),
                4 => (h.root.join("node/ledger-header.json"), b"{}".to_vec()),
                5 => (
                    h.root.join("node/ledger-events/stream.json"),
                    b"{}".to_vec(),
                ),
                _ => return,
            };
            crate::keystore::private_create(
                &h.root.join("attack-original-bytes"),
                &fs::read(&path).unwrap(),
            )
            .unwrap();
            fs::write(path, raw).unwrap();
            *after_attack.borrow_mut() = Some(inventory(&h.root));
        };
        let result = h.agents[0].probe_local_cursor(
            &h.node,
            request,
            |message| Approval {
                key: public(h.seeds[0]),
                signature: if attack == 1 {
                    "00".repeat(64)
                } else {
                    signature(h.seeds[0], &message.bytes().unwrap())
                },
            },
            || {
                if attack != 3 {
                    mutate();
                }
            },
            || {
                if attack == 3 {
                    mutate();
                }
            },
        );
        if attack == 0 {
            let state = result.unwrap();
            assert_eq!(state.round, 1);
        } else {
            let error = result.unwrap_err();
            if attack == 1 {
                assert!(
                    error.contains("signature"),
                    "new complete signature must authenticate: {error}"
                );
            }
            if attack == 2 || attack == 3 {
                assert!(
                    error.contains("pending native incident"),
                    "both boundaries must check native guard: {error}"
                );
            }
        }
        assert_eq!(
            inventory(&h.root),
            after_attack.into_inner().unwrap_or(before)
        );
        assert_eq!(h.agents[0].head().unwrap(), h.heads[0]);
        println!("paged-cursor attack={attack} expected_result=true original_signer_head_unchanged=true native_height=2 no_probe_vote_published=true");
    }
}
