//! Actual user input is checked before value execution. Historical signed
//! facts retain their full bytes for independent conflict authentication.
use super::*;

fn request() -> wallet::Request {
    wallet::Request {
        owner: tests::public(10),
        participants: vec![],
        inputs: None,
        outputs: vec![Payment {
            owner: tests::public(11),
            amount: Amount(1),
        }],
        remote: Some(wallet::Remote {
            destination: Hash([4; 32]),
            recipient: Payment {
                owner: tests::public(12),
                amount: Amount(2),
            },
            destination_fee: Amount::ZERO,
        }),
        fee: Amount::ZERO,
        valid_for_blocks: 2,
        valid_through: None,
    }
}
#[test]
fn actual_wallet_request_parser_bounds_outputs_remote_and_fees_before_review() {
    let valid = request();
    let original = serde_json::to_vec(&valid).unwrap();
    let decoded: wallet::Request = serde_json::from_slice(&original).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), original);
    for amount in [Amount::TOTAL_SUPPLY.0 + 1, u128::MAX] {
        for field in 0..4 {
            let mut wire = serde_json::to_value(&valid).unwrap();
            let value = serde_json::json!(amount.to_string());
            match field {
                0 => wire["outputs"][0]["amount"] = value,
                1 => wire["remote"]["recipient"]["amount"] = value,
                2 => wire["fee"] = value,
                _ => wire["remote"]["destination_fee"] = value,
            }
            assert!(
                serde_json::from_value::<wallet::Request>(wire).is_err(),
                "actual wallet request accepted over-cap monetary field{field}"
            );
        }
    }
    let mut zero = serde_json::to_value(&valid).unwrap();
    zero["outputs"][0]["amount"] = serde_json::json!("0");
    assert!(serde_json::from_value::<wallet::Request>(zero).is_err());
    let mut zero = serde_json::to_value(&valid).unwrap();
    zero["remote"]["recipient"]["amount"] = serde_json::json!("0");
    assert!(serde_json::from_value::<wallet::Request>(zero).is_err());
    for raw in [
        "01",
        "-1",
        "+1",
        "1.5",
        "340282366920938463463374607431768211456",
    ] {
        let mut wire = serde_json::to_value(&valid).unwrap();
        wire["outputs"][0]["amount"] = serde_json::json!(raw);
        assert!(serde_json::from_value::<wallet::Request>(wire).is_err());
    }
    let duplicate = String::from_utf8(original).unwrap().replacen(
        "\"fee\":\"0\"",
        "\"fee\":\"0\",\"fee\":\"1\"",
        1,
    );
    assert!(serde_json::from_str::<wallet::Request>(&duplicate).is_err());
}

#[test]
fn group_builder_bounds_unsigned_money_and_preserves_wide_historical_facts() {
    let valid = request();
    let mut wire = serde_json::to_value(&valid).unwrap();
    wire.as_object_mut().unwrap().remove("valid_through");
    for field in 0..4 {
        let mut bad = wire.clone();
        let value = serde_json::json!(u128::MAX.to_string());
        match field {
            0 => bad["outputs"][0]["amount"] = value,
            1 => bad["fee"] = value,
            2 => bad["remote"]["recipient"]["amount"] = value,
            _ => bad["remote"]["destination_fee"] = value,
        }
        assert!(serde_json::from_value::<wallet_proposal::BuildRequest>(bad).is_err());
    }
    assert!(serde_json::from_value::<wallet_proposal::BuildRequest>(wire).is_ok());
    let mut maximum = request();
    maximum.outputs[0].amount = Amount::TOTAL_SUPPLY;
    assert_eq!(
        serde_json::from_slice::<wallet::Request>(&serde_json::to_vec(&maximum).unwrap()).unwrap(),
        maximum
    );
    let historical = Payment {
        owner: tests::public(10),
        amount: Amount(u128::MAX),
    };
    assert_eq!(
        serde_json::from_slice::<Payment>(&serde_json::to_vec(&historical).unwrap()).unwrap(),
        historical
    );
    let ledger = Ledger {
        received: Amount(u128::MAX),
        ..Ledger::default()
    };
    assert_eq!(
        serde_json::from_slice::<Ledger>(&serde_json::to_vec(&ledger).unwrap()).unwrap(),
        ledger
    );
    assert!(Amount(u128::MAX).checked_add(Amount(1)).is_err());
}

#[test]
fn typed_wallet_single_and_group_requests_refuse_before_review_without_mutation() {
    let (_root, node, _, _) = tests::channel_receipts::setup(None);
    let original_head = node.storage_head().unwrap();
    let original_ledger = node.chain.ledger.clone();
    for group in [false, true] {
        for field in 0..5 {
            let mut bad = request();
            if group {
                bad.participants = vec![tests::public(10), tests::public(11)];
            }
            match field {
                0 => bad.outputs[0].amount = Amount::ZERO,
                1 => bad.outputs[0].amount = Amount(Amount::TOTAL_SUPPLY.0 + 1),
                2 => bad.fee = Amount(u128::MAX),
                3 => bad.remote.as_mut().unwrap().recipient.amount = Amount::ZERO,
                _ => bad.remote.as_mut().unwrap().destination_fee = Amount(u128::MAX),
            }
            let error = wallet::prepare(&node, bad).unwrap_err();
            assert!(error.starts_with("monetary "), "{error}");
            assert_eq!(node.storage_head().unwrap(), original_head);
            assert_eq!(node.chain.ledger, original_ledger);
        }
    }
}
