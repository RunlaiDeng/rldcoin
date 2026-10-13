use super::*;

fn diagnostic_bundle() -> Value {
    // Metadata-only trace input, never a signed exchange or Native authority.
    json!({"body":{"transits":[{"routing":{"body":{
        "packet_id":"packet","frame_id":"frame"}},
        "packet":{"body":{"destination":"destination"}}}]}})
}

#[test]
fn duration_aggregation_preserves_exact_carriage_capacity_and_counts() {
    start_work_trace();
    for _ in 0..4096 {
        trace_work("mesh-prepare", monotonic().unwrap()).unwrap();
    }
    let exchange = trace_exchange("published-transport-exchange", "peer", &diagnostic_bundle());
    let records = take_work_trace();
    let work = records
        .iter()
        .filter(|row| row["phase"] == "mesh-prepare")
        .collect::<Vec<_>>();
    let calls = work
        .iter()
        .map(|row| row["calls"].as_u64().unwrap_or(1))
        .sum::<u64>();
    eprintln!(
        "Duration trace counter: {}",
        json!({
            "duration_records":work.len(),"duration_calls":calls,
            "total_records":records.len(),"exact_exchange_error":exchange.as_ref().err(),
            "ledger_authority":false
        })
    );
    assert!(
        exchange.is_ok(),
        "phase-only durations exhausted exact carriage capacity: {exchange:?}"
    );
    assert_eq!(work.len(), 1);
    assert_eq!(calls, 4096);
    assert!(work[0]["seconds"]
        .as_f64()
        .is_some_and(|seconds| seconds.is_finite() && seconds >= 0.0));
    assert_eq!(records.len(), 2);
    let exact = records
        .iter()
        .find(|row| row["phase"] == "published-transport-exchange")
        .unwrap();
    assert_eq!(exact["peer"], "peer");
    assert!(exact["at"]
        .as_f64()
        .is_some_and(|at| at.is_finite() && at >= 0.0));
    assert_eq!(
        exact["packets"],
        json!([{"packet_id":"packet","frame_id":"frame","destination":"destination"}])
    );
}

#[test]
fn exact_carriage_bound_refuses_without_dropping_retained_events() {
    start_work_trace();
    for _ in 0..4096 {
        trace_exchange("published-transport-exchange", "peer", &diagnostic_bundle()).unwrap();
    }
    let before = CARRIAGE_TRACE.with(|trace| trace.borrow().clone().unwrap());
    let error =
        trace_exchange("published-transport-exchange", "peer", &diagnostic_bundle()).unwrap_err();
    assert_eq!(error, "diagnostic carriage record bound");
    PAYMENT_TRACE_ACTIVE.with(|active| active.set(true));
    assert_eq!(
        trace_payment_event(|| Ok(json!({"phase":"payment-test"}))).unwrap_err(),
        error
    );
    let retained = take_work_trace();
    assert_eq!(retained, before);
    assert_eq!(retained.len(), 4096);
    assert!(!PAYMENT_TRACE_ACTIVE.with(|active| active.get()));
    assert!(take_work_trace().is_empty());
}

#[test]
fn work_uses_the_existing_phase_bound_and_resets_without_stale_records() {
    const PHASES: [&str; 64] = [
        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12", "13", "14",
        "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "43", "44",
        "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
        "60", "61", "62", "63",
    ];
    start_work_trace();
    for phase in PHASES {
        trace_subwork(phase, monotonic().unwrap()).unwrap();
    }
    let before = SUBWORK_TRACE.with(|trace| trace.borrow().clone());
    assert_eq!(
        trace_work("additional-work-phase", monotonic().unwrap()).unwrap_err(),
        "diagnostic subwork phase bound"
    );
    assert_eq!(SUBWORK_TRACE.with(|trace| trace.borrow().clone()), before);
    trace_work(PHASES[0], monotonic().unwrap()).unwrap();
    let records = take_work_trace();
    assert_eq!(records.len(), 64);
    assert_eq!(
        records
            .iter()
            .find(|row| row["phase"] == PHASES[0])
            .unwrap()["calls"],
        2
    );
    start_work_trace();
    trace_work("fresh-phase", monotonic().unwrap()).unwrap();
    let fresh = take_work_trace();
    assert_eq!(fresh.len(), 1);
    assert_eq!(fresh[0]["phase"], "fresh-phase");
    assert_eq!(fresh[0]["calls"], 1);
    assert!(take_work_trace().is_empty());
}
