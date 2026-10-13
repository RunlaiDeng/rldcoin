//! Reader-only metadata diagnostic. These traces grant no Native authority.
//! Joins exact original events after the existing single-payment fixture stops.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum PrepareTraceKind {
    Prepare,
    Commit,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareTraceVote {
    kind: PrepareTraceKind,
    context: bft::Context,
    round: u64,
    value: Hash,
    signer: Hash,
}

#[derive(Clone)]
struct PrepareAvailability {
    signer: Hash,
    source_actor: usize,
    body: Hash,
    frame: Option<Hash>,
    packet: Option<Hash>,
    at: f64,
    event_index: usize,
    local: bool,
}

fn prepare_vote(event: &Value) -> Result<Option<PrepareTraceVote>> {
    if !matches!(event["body"]["kind"].as_str(), Some("prepare" | "commit")) {
        return Ok(None);
    }
    let vote: PrepareTraceVote =
        serde_json::from_value(event["body"].clone()).map_err(|e| e.to_string())?;
    require(
        !vote.value.is_zero() && !vote.signer.is_zero(),
        "Prepare trace vote identity missing",
    )?;
    Ok(Some(vote))
}

fn prepare_actor(actors: &[(Hash, Hash); 4], signer: Hash) -> Result<usize> {
    actors
        .iter()
        .position(|(key, _)| *key == signer)
        .ok_or("Prepare trace signer is outside original fixture admission".into())
}

fn prepare_packets(event: &Value, bound: usize) -> Result<&Vec<Value>> {
    let packets = event["packets"]
        .as_array()
        .ok_or("Prepare trace packet list missing")?;
    require(packets.len() <= bound, "Prepare trace packet bound")?;
    let mut seen = BTreeSet::new();
    for packet in packets {
        let id = trace_hash(&packet["packet_id"])?;
        trace_hash(&packet["frame_id"])?;
        trace_hash(&packet["destination"])?;
        require(seen.insert(id), "Prepare trace duplicate packet identity")?;
    }
    Ok(packets)
}

fn prepare_contains(event: &Value, packet: Hash, frame: Hash, destination: Hash) -> bool {
    // Every packet row was already typed and bounded by load_prepare_events.
    event["packets"].as_array().is_some_and(|packets| {
        packets.iter().any(|row| {
            row["packet_id"] == json!(packet)
                && row["frame_id"] == json!(frame)
                && row["destination"] == json!(destination)
        })
    })
}

fn load_prepare_events(root: &Path, actors: &[(Hash, Hash); 4]) -> Result<[Vec<Value>; 4]> {
    let mut keys = BTreeSet::new();
    let mut nodes = BTreeSet::new();
    for (key, node) in actors {
        require(
            !key.is_zero() && !node.is_zero() && keys.insert(*key) && nodes.insert(*node),
            "Prepare trace fixture requires four distinct signer and node identities",
        )?;
    }
    let mut all: [Vec<Value>; 4] = std::array::from_fn(|_| Vec::new());
    for actor in 0..4 {
        let trace = read(
            &root.join(format!("carriage-ledger-{actor}.json")),
            4 * 1024 * 1024,
        )?;
        let events = trace["events"]
            .as_array()
            .ok_or("Prepare trace event list missing")?;
        require(events.len() <= 4160, "Prepare trace event bound")?;
        let mut last_at = None;
        for event in events {
            validate_event(event)?;
            let phase = event["phase"]
                .as_str()
                .ok_or("Prepare trace phase missing")?;
            if let Some(clock) = event.get("at") {
                let at = trace_time(clock)?;
                require(
                    last_at.is_none_or(|last| last <= at),
                    "Prepare trace actor event clocks moved backwards",
                )?;
                last_at = Some(at);
            }
            if matches!(phase, "payment-body-retained" | "payment-envelope-received") {
                if let Some(vote) = prepare_vote(event)? {
                    prepare_actor(actors, vote.signer)?;
                    if phase == "payment-body-retained" {
                        let local = event["local"]
                            .as_bool()
                            .ok_or("Prepare trace retention role missing")?;
                        if local {
                            require(
                                vote.signer == actors[actor].0,
                                "Prepare trace local vote signer differs from original actor",
                            )?;
                        }
                    }
                }
            }
            match phase {
                "payment-packets-queued" => {
                    trace_time(&event["at"])?;
                    require(
                        trace_hash(&event["node_id"])? == actors[actor].1,
                        "Prepare queue node differs from original actor",
                    )?;
                    require(
                        !prepare_packets(event, 64)?.is_empty(),
                        "Prepare queue event has no new packet",
                    )?;
                }
                "payment-transport-prepared" => {
                    require(
                        trace_hash(&event["node_id"])? == actors[actor].1
                            && nodes.contains(&trace_hash(&event["peer"])?)
                            && trace_time(&event["started"])? <= trace_time(&event["at"])?,
                        "Prepare selected turn identity or original clock differs",
                    )?;
                    prepare_packets(event, 4)?;
                }
                "published-transport-exchange" | "durable-transport-receive" => {
                    trace_time(&event["at"])?;
                    require(
                        nodes.contains(&trace_hash(&event["peer"])?),
                        "Prepare carriage peer is outside original fixture",
                    )?;
                    prepare_packets(event, 4)?;
                }
                "native-receive" => {
                    trace_time(&event["at"])?;
                    trace_hash(&event["packet_id"])?;
                    trace_hash(&event["frame_id"])?;
                }
                _ => {}
            }
        }
        all[actor] = events.clone();
    }
    Ok(all)
}

fn prepare_one<'a>(
    mut records: impl Iterator<Item = &'a Value>,
    reason: &str,
) -> Result<&'a Value> {
    let record = records.next().ok_or_else(|| reason.to_owned())?;
    require(records.next().is_none(), reason)?;
    Ok(record)
}

fn prepare_native_after(
    events: &[Value],
    envelope_index: usize,
    frame: Hash,
) -> Result<(usize, &Value)> {
    let (index, native) = events
        .iter()
        .enumerate()
        .skip(envelope_index + 1)
        .find(|(_, event)| {
            matches!(
                event["phase"].as_str(),
                Some("native-receive" | "payment-envelope-received")
            )
        })
        .ok_or("Prepare envelope has no subsequent Native receive")?;
    require(
        native["phase"] == "native-receive"
            && trace_hash(&native["frame_id"])? == frame
            && trace_time(&events[envelope_index]["at"])? <= trace_time(&native["at"])?,
        "Prepare envelope to Native receive linkage is missing or ambiguous",
    )?;
    Ok((index, native))
}

fn prepare_ratio(retained: f64, published: f64, accepted: f64) -> Result<f64> {
    require(
        retained.is_finite()
            && published.is_finite()
            && accepted.is_finite()
            && retained >= 0.0
            && retained <= published
            && published <= accepted
            && retained < accepted,
        "Prepare transport ratio needs complete ordered original clocks",
    )?;
    Ok((published - retained) / (accepted - retained))
}

/// actors are (original admitted signer key, initialized transport node ID),
/// captured before starting worker threads. Never derive them from trace claims.
pub(super) fn bind_prepare_transport(
    root: &Path,
    sample: &Sample,
    recipient: &PaymentObservation,
    binding: &Value,
    actors: &[(Hash, Hash); 4],
) -> Result<Value> {
    let events = load_prepare_events(root, actors)?;
    let candidates = binding["candidates"]
        .as_array()
        .ok_or("Prepare trace is missing original proposal binding")?;
    require(candidates.len() <= 128, "Prepare candidate bound")?;
    let mut accepted_candidates = Vec::new();
    for candidate in candidates {
        if completed_candidate(sample, recipient, candidate)? {
            accepted_candidates.push(candidate);
        }
    }
    require(
        accepted_candidates.len() == 1,
        "Prepare trace accepted proposal/round is missing or ambiguous",
    )?;
    let candidate = accepted_candidates[0];
    let leader = candidate["actor"]
        .as_u64()
        .filter(|actor| *actor < 4)
        .ok_or("Prepare proposal leader actor missing")? as usize;
    let context: bft::Context =
        serde_json::from_value(candidate["context"].clone()).map_err(|e| e.to_string())?;
    let round = candidate["round"]
        .as_u64()
        .ok_or("Prepare proposal round missing")?;
    let value = trace_hash(&candidate["snapshot"]["value"])?;
    let proposal_body = trace_hash(&candidate["signed_proposal_body"])?;
    let proposal_at = trace_time(&candidate["signed_proposal_retained"])?;
    require(
        context.parent_height.checked_add(1) == recipient.created,
        "Prepare proposal context does not precede exact output creation",
    )?;
    let proposal = prepare_one(
        events[leader].iter().filter(|event| {
            event["phase"] == "payment-body-retained"
                && event["local"] == true
                && event["body_id"] == json!(proposal_body)
        }),
        "Prepare original local signed proposal is missing or repeated",
    )?;
    require(
        proposal["body"]["kind"] == "proposal"
            && proposal["body"]["context"] == candidate["context"]
            && proposal["body"]["round"] == candidate["round"]
            && proposal["body"]["snapshot"] == candidate["snapshot"]
            && trace_hash(&proposal["body"]["leader"])? == actors[leader].0
            && trace_time(&proposal["at"])? == proposal_at,
        "Prepare proposal trace differs from original accepted binding",
    )?;

    let mut first = BTreeMap::<Hash, PrepareAvailability>::new();
    let mut arrival_count = 0usize;
    for (index, event) in events[leader].iter().enumerate() {
        let phase = event["phase"].as_str().ok_or("Prepare event phase")?;
        if !matches!(phase, "payment-body-retained" | "payment-envelope-received") {
            continue;
        }
        let Some(vote) = prepare_vote(event)? else {
            continue;
        };
        if vote.kind != PrepareTraceKind::Prepare
            || vote.context != context
            || vote.round != round
            || vote.value != value
        {
            continue;
        }
        let body = trace_hash(&event["body_id"])?;
        let source_actor = prepare_actor(actors, vote.signer)?;
        let available = if phase == "payment-body-retained" && event["local"] == true {
            PrepareAvailability {
                signer: vote.signer,
                source_actor,
                body,
                frame: None,
                packet: None,
                at: trace_time(&event["at"])?,
                event_index: index,
                local: true,
            }
        } else if phase == "payment-envelope-received" {
            let frame = trace_hash(&event["frame_id"])?;
            let (native_index, native) = prepare_native_after(&events[leader], index, frame)?;
            PrepareAvailability {
                signer: vote.signer,
                source_actor,
                body,
                frame: Some(frame),
                packet: Some(trace_hash(&native["packet_id"])?),
                at: trace_time(&native["at"])?,
                event_index: native_index,
                local: false,
            }
        } else {
            continue;
        };
        // Votes after the recipient endpoint cannot establish earlier availability.
        if available.at > recipient.native_verified_at {
            continue;
        }
        require(
            proposal_at <= available.at,
            "Prepare availability predates the exact signed proposal",
        )?;
        arrival_count += 1;
        if let Some(prior) = first.get(&vote.signer) {
            require(
                prior.body == body && prior.at <= available.at,
                "Prepare signer has ambiguous body identity or arrival ordering",
            )?;
        } else {
            first.insert(vote.signer, available);
        }
    }
    require(
        first.len() >= 3,
        "Prepare trace has fewer than three distinct native-available votes",
    )?;
    let mut available = first.into_values().collect::<Vec<_>>();
    available.sort_by(|a, b| {
        a.at.total_cmp(&b.at)
            .then(a.event_index.cmp(&b.event_index))
    });
    let third = &available[2];
    require(
        !third.local && third.source_actor != leader,
        "third Prepare is local; no remote transport path is established",
    )?;
    let source = third.source_actor;
    let frame = third.frame.ok_or("third Prepare frame missing")?;
    let packet = third.packet.ok_or("third Prepare packet missing")?;
    let destination = actors[leader].1;
    let origin = prepare_one(
        events[source].iter().filter(|event| {
            event["phase"] == "payment-body-retained"
                && event["local"] == true
                && event["body_id"] == json!(third.body)
        }),
        "Prepare original local retention is missing or ambiguous",
    )?;
    let original_vote = prepare_vote(origin)?.ok_or("Prepare original typed vote missing")?;
    require(
        original_vote.kind == PrepareTraceKind::Prepare
            && original_vote.context == context
            && original_vote.round == round
            && original_vote.value == value
            && original_vote.signer == third.signer,
        "Prepare original local vote differs from the receiving leader",
    )?;
    let retained = trace_time(&origin["at"])?;
    let frame_prepared = events[source]
        .iter()
        .find(|event| {
            event["phase"] == "payment-frame-prepared"
                && event["body_id"] == json!(third.body)
                && event["frame_id"] == json!(frame)
        })
        .ok_or("Prepare original body has no exact constructed frame")?;
    let frame_at = trace_time(&frame_prepared["at"])?;
    let queue = prepare_one(
        events[source].iter().filter(|event| {
            event["phase"] == "payment-packets-queued"
                && prepare_contains(event, packet, frame, destination)
        }),
        "Prepare first new-packet durable queue is missing or repeated",
    )?;
    let queued = trace_time(&queue["at"])?;

    // Use the first actual destination custody of this packet. A relayed first
    // receipt is a different route; refuse rather than attribute it to a direct hop.
    let durable = events[leader]
        .iter()
        .find(|event| {
            event["phase"] == "durable-transport-receive"
                && prepare_contains(event, packet, frame, destination)
        })
        .ok_or("Prepare exact destination durable custody missing")?;
    require(
        trace_hash(&durable["peer"])? == actors[source].1,
        "Prepare first custody used a relay; direct path is not established",
    )?;
    let durable_at = trace_time(&durable["at"])?;
    let publications = events[source]
        .iter()
        .filter(|event| {
            event["phase"] == "published-transport-exchange"
                && event["peer"] == json!(destination)
                && prepare_contains(event, packet, frame, destination)
                && event["at"].as_f64().is_some_and(|at| at <= durable_at)
        })
        .collect::<Vec<_>>();
    let published = *publications
        .first()
        .ok_or("Prepare publication before first custody is missing")?;
    let published_at = trace_time(&published["at"])?;
    let published_index = events[source]
        .iter()
        .position(|event| std::ptr::eq(event, published))
        .ok_or("Prepare publication index missing")?;
    let prepared = events[source][..published_index]
        .iter()
        .rev()
        .find(|event| {
            event["phase"] == "payment-transport-prepared" && event["peer"] == json!(destination)
        })
        .ok_or("Prepare publication has no observed ordinary prepared turn")?;
    require(
        prepared["packets"] == published["packets"]
            && prepare_contains(prepared, packet, frame, destination),
        "Prepare selected turn differs from actual published packet batch",
    )?;
    let turn_started = trace_time(&prepared["started"])?;
    let selected_at = trace_time(&prepared["at"])?;
    require(
        proposal_at <= retained
            && retained <= frame_at
            && frame_at <= queued
            && queued <= turn_started
            && turn_started <= selected_at
            && selected_at <= published_at
            && published_at <= durable_at
            && durable_at <= third.at
            && third.at <= recipient.native_verified_at,
        "Prepare exact transport path has missing or out-of-order original clocks",
    )?;
    let ratio = prepare_ratio(retained, published_at, third.at)?;
    let quorum = available
        .iter()
        .map(|row| {
            json!({
                "signer":row.signer, "source_actor":row.source_actor, "body_id":row.body,
                "native_available_at":row.at, "local":row.local,
                "leader_event_index":row.event_index
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "value":value, "context":context, "round":round,
        "signed_proposal_body":proposal_body, "leader_actor":leader,
        "third_prepare":{"source_actor":source, "signer":third.signer,
            "body_id":third.body, "frame_id":frame, "packet_id":packet,
            "destination":destination},
        "quorum_available_at":third.at, "first_distinct_votes":quorum,
        "authenticated_arrival_count":arrival_count,
        "publication_count_before_first_custody":publications.len(),
        "single_observed_publication_before_first_custody":publications.len() == 1,
        "clocks":{"local_retained":retained, "frame_prepared":frame_at,
            "first_durable_queue":queued, "ordinary_prepare_started":turn_started,
            "ordinary_prepare_completed":selected_at, "published":published_at,
            "destination_durable":durable_at, "destination_native":third.at},
        "seconds":{"retain_to_queue":queued-retained,
            "queue_to_containing_turn":turn_started-queued,
            "containing_turn":selected_at-turn_started,
            "prepared_to_published":published_at-selected_at,
            "published_to_destination_durable":durable_at-published_at,
            "destination_durable_to_native":third.at-durable_at,
            "total":third.at-retained},
        "before_publication_fraction":ratio,
        "hypothesis_more_than_half_before_publication":ratio > 0.5,
        "decision":if ratio > 0.5 {"inspect_measured_source_segment"} else {"first_publication_majority_hypothesis_falsified"},
        "scope":"same-host direct carriage of observed third distinct Prepare",
        "publication_scope":"First observed publication to first custody is an original-clock interval, not network latency or identification of the delivery attempt. Retransmissions cannot invalidate the first-publication fraction but may move the actual delivering attempt later.",
        "selected_qc_observed":false, "commit_cause_qualified":false,
        "ledger_authority":false, "latency_percentiles_qualified":false
    }))
}

#[test]
fn prepare_metadata_guards_reject_missing_duplicate_and_nonmonotonic_data() {
    // Synthetic reader cases only: these do not authenticate a vote or fixture.
    let id = Hash([7; 32]);
    let context = bft::Context {
        currency: Hash([1; 32]),
        region: Hash([2; 32]),
        epoch: Hash([3; 32]),
        previous: Some(Hash([4; 32])),
        parent_height: 4,
        parent_block: Hash([5; 32]),
        parent_state: Hash([6; 32]),
    };
    let mut vote = json!({"body":{"kind":"prepare","context":context,
        "round":0,"value":id,"signer":Hash([8;32])}});
    assert!(prepare_vote(&vote).unwrap().is_some());
    vote["body"].as_object_mut().unwrap().remove("signer");
    assert!(prepare_vote(&vote).is_err());
    let repeated = [json!({"at":1.0}), json!({"at":1.0})];
    assert!(prepare_one(repeated.iter(), "ambiguous").is_err());
    assert!(prepare_packets(&json!({"packets":null}), 4).is_err());
    let row = json!({"packet_id":id,"frame_id":Hash([8;32]),"destination":Hash([9;32])});
    assert!(prepare_packets(&json!({"packets":[row.clone(),row]}), 4).is_err());
    assert!(prepare_native_after(
        &[
            json!({"phase":"payment-envelope-received","at":2.0}),
            json!({"phase":"payment-envelope-received","at":3.0}),
            json!({"phase":"native-receive","frame_id":id,"at":4.0})
        ],
        0,
        id
    )
    .is_err());
    assert!(prepare_native_after(
        &[
            json!({"phase":"payment-envelope-received","at":2.0}),
            json!({"phase":"native-receive","frame_id":id,"at":1.0})
        ],
        0,
        id
    )
    .is_err());
    assert!(prepare_ratio(1.0, 2.0, 1.0).is_err());
    assert!(prepare_ratio(1.0, f64::NAN, 3.0).is_err());
    assert!(prepare_ratio(0.0, 4.0, 3.0).is_err());
    assert_eq!(prepare_ratio(1.0, 2.0, 3.0).unwrap(), 0.5);
    assert!(prepare_ratio(1.0, 2.5, 3.0).unwrap() > 0.5);
}
