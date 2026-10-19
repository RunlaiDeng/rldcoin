//! Interactive fast workflow over the same exact native/caller authorization.
//! Menus choose retained public data; no peer packet supplies owner consent.
use super::*;
use rld_survivor_node::fast_session::{FeePolicy, OnchainRequest, OpeningRequest, OpeningTerms};

fn choose(label: &str, rows: &[Value]) -> Result<Value> {
    if rows.is_empty() {
        return Err(format!("No {label} available"));
    }
    for (i, row) in rows.iter().enumerate() {
        println!("{}: {}", i + 1, row);
    }
    let n = text(&format!("Choose {label} number"))?
        .parse::<usize>()
        .map_err(|_| "Use a listed number")?;
    rows.get(n.wrapping_sub(1))
        .cloned()
        .ok_or("Choose a listed number".into())
}
fn positive(label: &str) -> Result<u128> {
    let n = amount(&text(label)?)?;
    if n == 0 {
        return Err("Amount must be positive".into());
    }
    Ok(n)
}
fn index() -> Result<u8> {
    match text("Your agreed channel owner position (0 or 1)")?.as_str() {
        "0" => Ok(0),
        "1" => Ok(1),
        _ => Err("Owner position must be 0 or 1".into()),
    }
}
fn show(v: &Value) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v).map_err(fail)?);
    Ok(())
}
impl Wallet {
    fn evaluation_time(&self) -> Result<String> {
        Ok(now()?
            .max(
                self.node
                    .stamp
                    .checked_add(1)
                    .ok_or("Native clock overflow")?,
            )
            .to_string())
    }
    fn actor(&mut self, retainer: Option<bool>) -> Result<(Id, u8)> {
        let status = self.node.refresh()?;
        let rows = status["actor_scopes"]
            .as_array()
            .ok_or("Missing native actor scopes")?
            .iter()
            .filter(|v| {
                v["role"]
                    .as_u64()
                    .is_some_and(|r| r <= 2 && retainer.is_none_or(|retainer| retainer == (r == 2)))
            })
            .cloned()
            .collect::<Vec<_>>();
        let row = choose("channel role", &rows)?;
        Ok((
            field_id(&row, "actor")?,
            row["role"].as_u64().unwrap() as u8,
        ))
    }
    fn destination(&mut self) -> Result<Id> {
        self.node.refresh()?;
        let v = self.node.call(json!({"command":"peer_status"}), None)?;
        let row = choose(
            "configured neighbor",
            v["neighbors"]
                .as_array()
                .ok_or("Missing admitted neighbors")?,
        )?;
        serde_json::from_value(row).map_err(fail)
    }
    fn packet(&mut self, kind: u8) -> Result<Id> {
        self.node.refresh()?;
        let v = self.node.call(json!({"command":"peer_inventory"}), None)?;
        let rows = v["packets"]
            .as_array()
            .ok_or("Missing retained packet inventory")?
            .iter()
            .filter(|v| v["received"] == true && v["kind"].as_u64() == Some(kind as u64))
            .cloned()
            .collect::<Vec<_>>();
        field_id(&choose("received packet", &rows)?, "id")
    }
    fn queued(&mut self, request: Value) -> Result<()> {
        self.node.refresh()?;
        let v = self.node.call(request, None)?;
        show(&v)?;
        println!("Data queued. Transport custody does not establish payment completion.");
        Ok(())
    }
    fn register_fast(&mut self) -> Result<()> {
        let channel = parse_id(&text("Native included funding channel")?)?;
        let delegation = text("Funding miner's public delegation certificate")?;
        let role = text("Role: owner or retainer")?;
        let own = if role == "owner" {
            Some(index()?)
        } else {
            None
        };
        if role != "owner" && role != "retainer" {
            return Err("Choose owner or retainer".into());
        }
        self.node.refresh()?;
        let action = if let Some(owner) = own {
            Action::OwnerCreate {
                tip: self.node.tip,
                channel,
                owner,
                delegation,
            }
        } else {
            Action::RetainerCreate {
                tip: self.node.tip,
                channel,
                delegation,
            }
        };
        let (_, v) = self.node.execute(action, None)?;
        show(&v)?;
        println!("Local custody role registered; no payment has been signed.");
        Ok(())
    }
    fn fast_sign(&mut self, prepared: Id, v: Value, actor: Id, role: u8) -> Result<()> {
        let a = self.selected()?;
        let review = &v["review"];
        let required = field_id(review, if role == 2 { "retainer" } else { "owner" })?;
        if required != a.owner {
            return Err("Selected wallet is not this role's actual native signing owner".into());
        }
        println!("Exact native fast-payment review:");
        show(review)?;
        if role < 2 {
            println!(
                "Amount: {} RLD; fee to funding miner: {} RLD",
                display_amount(number(&review["amount"])?),
                display_amount(number(&review["fee"])?)
            );
            println!("Your signature approves this exact jointly signed balance transition.");
        } else {
            println!("Your signature acknowledges durable full-receipt custody, with no principal spending rights.");
        }
        if !approve()? {
            println!("Preparation retained unsigned. Its reservation remains pending.");
            return Ok(());
        }
        let key = secret("Wallet password")?;
        let review_id = field_id(&v, "review_digest")?;
        let action = if role < 2 {
            Action::OwnerSign {
                tip: self.node.tip,
                actor,
                invoice: field_id(review, "invoice_id")?,
                review_request: prepared,
                review: review_id,
                key_file: a.path,
                approved: true,
            }
        } else {
            Action::RetainerSign {
                tip: self.node.tip,
                actor,
                receipt: field_id(review, "receipt_id")?,
                review_request: prepared,
                review: review_id,
                key_file: a.path,
                approved: true,
            }
        };
        let (_, signed) = self.node.execute(action, Some(&key))?;
        show(&signed)?;
        println!("Local signature retained. Complete recipient custody remains a separate step.");
        Ok(())
    }
    fn fast_propose(&mut self) -> Result<()> {
        let a = self.selected()?;
        let (actor, role) = self.actor(Some(false))?;
        let state = self
            .node
            .call(json!({"command":"owner_state","actor":actor}), None)?;
        if field_id(&state, "owner")? != a.owner {
            return Err("Select this channel owner's wallet before proposing payment".into());
        }
        let value = positive("Fast amount in RLD")?;
        self.node.refresh()?;
        let proposal = self.node.call(
            json!({"command":"propose","actor":actor,"payer":role,
            "amount":value.to_string(),"invoice":rid()?}),
            None,
        )?;
        let invoice = proposal["invoice_hex"]
            .as_str()
            .ok_or("Missing native invoice")?
            .to_string();
        let (prepared, v) = self.node.execute(
            Action::OwnerPrepare {
                tip: self.node.tip,
                actor,
                invoice,
            },
            None,
        )?;
        self.fast_sign(prepared, v, actor, role)
    }
    fn fast_receive(&mut self, retainer: bool) -> Result<()> {
        let (actor, role) = self.actor(Some(retainer))?;
        let packet = self.packet(if retainer { 4 } else { 2 })?;
        self.node.refresh()?;
        let prepared = rid()?;
        let v = self.node.call(
            json!({"command":"peer_prepare","actor":actor,"packet":packet,"request_id":prepared}),
            None,
        )?;
        self.fast_sign(prepared, v, actor, role)
    }
    fn fast_resume(&mut self) -> Result<()> {
        let (actor, role) = self.actor(None)?;
        if role < 2 {
            let state = self
                .node
                .call(json!({"command":"owner_state","actor":actor}), None)?;
            show(&state)?;
            let pending = &state["pending_payment"];
            let invoice = field_id(pending, "invoice")?;
            if pending["own_signature_retained"] == true {
                let v = self.node.call(
                    json!({"command":"pending","actor":actor,"invoice":invoice}),
                    None,
                )?;
                show(&v)?;
                println!("Retained own signature exported without loading a key or changing the original clock.");
                return Ok(());
            }
        }
        let action = if role < 2 {
            Action::OwnerReview {
                tip: self.node.tip,
                actor,
            }
        } else {
            Action::RetainerReview {
                tip: self.node.tip,
                actor,
            }
        };
        let (prepared, v) = self.node.execute(action, None)?;
        self.fast_sign(prepared, v, actor, role)
    }
    fn fast_send(&mut self, partial: bool) -> Result<()> {
        let (actor, _) = self.actor(Some(false))?;
        let state = self
            .node
            .call(json!({"command":"owner_state","actor":actor}), None)?;
        let invoice = field_id(&state["pending_payment"], "invoice")?;
        let destination = self.destination()?;
        self.queued(
            json!({"command":if partial{"peer_partial"}else{"peer_invoice"},
            "actor":actor,"invoice":invoice,"destination":destination}),
        )
    }
    fn fast_combine(&mut self) -> Result<()> {
        let (actor, _) = self.actor(Some(false))?;
        let state = self
            .node
            .call(json!({"command":"owner_state","actor":actor}), None)?;
        let invoice = field_id(&state["pending_payment"], "invoice")?;
        let partial = self.packet(3)?;
        let destination = self.destination()?;
        self.queued(
            json!({"command":"peer_combine_send","actor":actor,"invoice":invoice,
            "partial":partial,"destinations":[destination]}),
        )
    }
    fn fast_ack(&mut self) -> Result<()> {
        let (actor, _) = self.actor(Some(true))?;
        let receipt = parse_id(&text(
            "Retained receipt identifier from the custody review",
        )?)?;
        let destination = self.destination()?;
        self.queued(
            json!({"command":"peer_ack","actor":actor,"receipt":receipt,"destination":destination}),
        )
    }
    fn fast_complete(&mut self) -> Result<()> {
        let (actor, _) = self.actor(Some(false))?;
        let state = self
            .node
            .call(json!({"command":"owner_state","actor":actor}), None)?;
        let invoice = field_id(&state["pending_payment"], "invoice")?;
        println!("Choose the counterparty's exact signature packet.");
        let partial = self.packet(3)?;
        println!("Choose the funding-miner-delegated receipt acknowledgment.");
        let ack = self.packet(5)?;
        self.node.refresh()?;
        self.node.call(
            json!({"command":"peer_complete","actor":actor,"invoice":invoice,
            "partial":partial,"ack":ack,"request_id":rid()?}),
            None,
        )?;
        let state = self
            .node
            .call(json!({"command":"owner_state","actor":actor}), None)?;
        show(&state)?;
        if state["conditional_onward_state_available"] == true {
            println!("Complete receipt and miner-fee evidence retained; onward state is usable under the displayed current native backing.");
        } else {
            println!("Proof retained. Current onward usability is unavailable; inspect the native backing and pending state above.");
        }
        Ok(())
    }
    fn open_channel(&mut self) -> Result<()> {
        let a = self.selected()?;
        let own = index()? as usize;
        let other = parse_id(&text("Other channel owner's public address")?)?;
        let mut owners = [other; 2];
        owners[own] = a.owner;
        let mut principal = [0u128; 2];
        let mut rates = [0u128; 2];
        let mut limits = [0u64; 2];
        let mut fees = [0u128; 2];
        for i in 0..2 {
            println!("Agreed terms for owner {i}: {}", hex::encode(owners[i].0));
            principal[i] = amount(&text("Principal in RLD (zero is allowed)")?)?;
            limits[i] = text("Payment slot count")?.parse::<u64>().map_err(fail)?;
            if limits[i] == 0 {
                return Err("Payment slots must be positive".into());
            }
            rates[i] = positive("Fee per fast payment in RLD")?;
            fees[i] = positive("This owner's opening operation fee in RLD")?;
        }
        let counterparty =
            text("Other owner's agreed ordered native input references (comma separated)")?
                .split(',')
                .map(|s| s.trim().to_string())
                .collect::<Vec<_>>();
        let needed = principal[own]
            .checked_add(
                rates[own]
                    .checked_mul(limits[own] as u128)
                    .ok_or("Fee reserve overflow")?,
            )
            .and_then(|n| n.checked_add(fees[own]))
            .ok_or("Opening budget overflow")?;
        self.node.refresh()?;
        let (own_inputs, _) = self.inputs(a.owner, needed)?;
        let mut inputs = [counterparty.clone(), counterparty];
        inputs[own] = own_inputs;
        let terms = OpeningTerms {
            nonce: rid()?,
            owners,
            principal: principal.map(|v| v.to_string()),
            limits: limits.map(|v| v.to_string()),
            rates: rates.map(|v| v.to_string()),
            fees: fees.map(|v| v.to_string()),
            expiry: self
                .node
                .height
                .checked_add(144)
                .ok_or("Opening expiry overflow")?
                .to_string(),
            inputs,
        };
        let timestamp = self.evaluation_time()?;
        let proposal = self.node.call(
            json!({"command":"opening_proposal","terms":terms,"timestamp":timestamp}),
            None,
        )?;
        let proposal = proposal["proposal_hex"]
            .as_str()
            .ok_or("Missing native opening proposal")?
            .to_string();
        self.review_sign(
            Action::OpenPrepare {
                tip: self.node.tip,
                plan: OpeningRequest {
                    proposal,
                    owner: own as u8,
                    timestamp,
                },
            },
            &a,
        )?;
        println!("Opening remains pending independent counterparty consent and native inclusion.");
        Ok(())
    }
    fn receive_opening(&mut self) -> Result<()> {
        let a = self.selected()?;
        let owner = index()?;
        let packet = self.packet(7)?;
        self.node.refresh()?;
        // The peer command only prepares. Reuse the exact returned review for
        // explicit local signing; received bytes never supply approval.
        let prepared = rid()?;
        let v = self.node.call(
            json!({"command":"peer_open_prepare","packet":packet,
            "request_id":prepared,"owner":owner,"timestamp":self.evaluation_time()?}),
            None,
        )?;
        self.sign_opening_review(prepared, v, &a)
    }
    fn sign_opening_review(&mut self, prepared: Id, v: Value, a: &Account) -> Result<()> {
        let r = &v["review"];
        let own = r["own_index"]
            .as_u64()
            .filter(|i| *i < 2)
            .ok_or("Missing native opening position")? as usize;
        let signer: Id = serde_json::from_value(r["owners"][own].clone()).map_err(fail)?;
        if signer != a.owner {
            return Err("Select the actual opening owner's wallet".into());
        }
        show(r)?;
        println!("Retained preparation: {}", hex::encode(prepared.0));
        println!(
            "Review identifier: {}",
            hex::encode(field_id(&v, "review_digest")?.0)
        );
        if !approve()? {
            return Ok(());
        }
        let password = secret("Wallet password")?;
        let (sign, _) = self.node.execute(
            Action::OnchainSign {
                tip: self.node.tip,
                prepare_request: prepared,
                review: field_id(&v, "review_digest")?,
                key_file: a.path.clone(),
                approved: true,
            },
            Some(&password),
        )?;
        println!(
            "Retained own partial signing request: {}",
            hex::encode(sign.0)
        );
        Ok(())
    }
    fn send_opening(&mut self) -> Result<()> {
        let source = parse_id(&text(
            "Retained opening preparation or own partial signing request",
        )?)?;
        let destination = self.destination()?;
        self.queued(
            json!({"command":"peer_opening","source_request":source,"destination":destination}),
        )
    }
    fn combine_opening(&mut self) -> Result<()> {
        let prepare = parse_id(&text("Your retained opening preparation request")?)?;
        let sign = parse_id(&text("Your retained partial signing request")?)?;
        let review = parse_id(&text("Your original review identifier")?)?;
        let packet = self.packet(8)?;
        self.node.refresh()?;
        let combined = rid()?;
        self.node.call(
            json!({"command":"peer_open_combine","packet":packet,"request_id":combined,
            "prepare_request":prepare,"sign_request":sign,"review":review}),
            None,
        )?;
        self.node.queue(combined)
    }
    fn native_exit(&mut self) -> Result<()> {
        let a = self.selected()?;
        let (actor, _) = self.actor(None)?;
        let kind = match text("Action: close, challenge, claim or settle")?.as_str() {
            "close" => 2,
            "challenge" => 3,
            "claim" => 4,
            "settle" => 5,
            _ => return Err("Choose a listed native action".into()),
        };
        let state = self.node.refresh()?;
        let channel = state["actor_scopes"]
            .as_array()
            .ok_or("Missing actor scopes")?
            .iter()
            .find(|v| v["actor"] == json!(actor))
            .ok_or("Missing selected actor scope")?;
        let channel = field_id(channel, "channel")?;
        let initial = if kind == 2 {
            match text("Close state: initial or latest")?.as_str() {
                "initial" => true,
                "latest" => false,
                _ => return Err("Choose initial or latest".into()),
            }
        } else {
            false
        };
        let certificate = if kind == 5 || initial {
            String::new()
        } else {
            let proof = self
                .node
                .call(json!({"command":"exit_evidence","actor":actor}), None)?;
            proof["certificate_hex"]
                .as_str()
                .ok_or("Missing retained certificate")?
                .to_string()
        };
        let fee = positive("Native operation fee in RLD")?;
        self.node.refresh()?;
        let (inputs, _) = self.inputs(a.owner, fee)?;
        let plan = OnchainRequest {
            kind,
            channel,
            actor: a.owner,
            inputs,
            fee: fee.to_string(),
            expiry: self
                .node
                .height
                .checked_add(144)
                .ok_or("Expiry overflow")?
                .to_string(),
            nonce: rid()?,
            certificate,
            timestamp: self.evaluation_time()?,
        };
        if let Some((signed, _)) = self.review_sign(
            Action::OnchainPrepare {
                tip: self.node.tip,
                plan,
            },
            &a,
        )? {
            self.node.queue(signed)?;
        }
        Ok(())
    }
    fn fee_monitor(&mut self) -> Result<()> {
        let a = self.selected()?;
        println!("This explicitly reserves ordinary fee-wallet inputs for bounded native protection. It grants no channel-owner signature rights.");
        let channel = parse_id(&text("Funded channel to protect")?)?;
        let max_fee = positive("Maximum native operation fee in RLD")?;
        let total_fee = positive("Total native fee budget in RLD")?;
        let max_operations = text("Maximum signed operations (1..64)")?
            .parse::<u16>()
            .map_err(fail)?;
        let hours = text("Consent duration in hours (1..744)")?
            .parse::<u64>()
            .map_err(fail)?;
        if !(1..=744).contains(&hours) || !(1..=64).contains(&max_operations) || max_fee > total_fee
        {
            return Err("Invalid explicit fee consent limits".into());
        }
        let status = self.node.refresh()?;
        let (mut inputs, _) = self.inputs(a.owner, total_fee)?;
        if inputs.len() > 8 {
            return Err("Fee policy permits at most 8 root inputs".into());
        }
        inputs.sort();
        let terms = FeePolicy {
            chain: field_id(&status, "chain")?,
            caller: field_id(&status, "caller_binding")?,
            owner: a.owner,
            channels: vec![channel],
            inputs,
            max_fee: max_fee.to_string(),
            total_fee: total_fee.to_string(),
            max_operations,
            expiry_height: text("Absolute last signing height")?,
            expiry_time: now()?
                .checked_add(hours * 3600)
                .ok_or("Policy expiry overflow")?
                .to_string(),
            nonce: rid()?,
        };
        show(&serde_json::to_value(&terms).map_err(fail)?)?;
        println!(
            "Maximum operation fee: {} RLD; total allowance: {} RLD",
            display_amount(max_fee),
            display_amount(total_fee)
        );
        if !approve()? {
            return Ok(());
        }
        let password = secret("Fee wallet password")?;
        let (request, v) = self.node.execute(
            Action::FeePolicyApprove {
                tip: self.node.tip,
                terms,
                key_file: a.path.clone(),
                approved: true,
            },
            Some(&password),
        )?;
        show(&v)?;
        println!("Retained fee policy: {}", hex::encode(request.0));
        println!("Start monitoring only for this exact retained consent?");
        if approve()? {
            self.start_monitor(request, &a, max_fee, Some(&password))?;
        }
        Ok(())
    }
    fn start_monitor(
        &mut self,
        policy: Id,
        a: &Account,
        fee: u128,
        password: Option<&[u8]>,
    ) -> Result<()> {
        self.node.refresh()?;
        self.node.call(
            json!({"command":"monitor_start","config":{"policy_request":policy,
            "key_file":a.path,"operation_fee":fee.to_string()}}),
            password,
        )?;
        println!("Local monitoring started. The runtime status reports faults and actual observations; this does not guarantee inclusion.");
        Ok(())
    }
    fn resume_monitor(&mut self) -> Result<()> {
        let a = self.selected()?;
        let policy = parse_id(&text("Retained fee policy request")?)?;
        self.node.refresh()?;
        let v = self.node.call(
            json!({"command":"fee_policy_status","policy_request":policy}),
            None,
        )?;
        show(&v)?;
        if field_id(&v, "fee_wallet")? != a.owner {
            return Err("Select the actual fee wallet".into());
        }
        let fee = positive("Native operation fee in RLD")?;
        println!("Unlock only the existing bounded policy for local monitoring?");
        if !approve()? {
            return Ok(());
        }
        let password = secret("Fee wallet password")?;
        self.start_monitor(policy, &a, fee, Some(&password))
    }
    fn resume_native_preparation(&mut self) -> Result<()> {
        let a = self.selected()?;
        let request = parse_id(&text("Retained native preparation request")?)?;
        self.node.refresh()?;
        let v = self.node.call(
            json!({"command":"native_preparation","prepare_request":request}),
            None,
        )?;
        println!("Historical preparation time: {}", v["original_prepared_at"]);
        show(&v["review"])?;
        let mut action: Action = serde_json::from_value(v["preparation"].clone()).map_err(fail)?;
        if v["retained_sign_request"].is_string() {
            let signed = field_id(&v, "retained_sign_request")?;
            match &action {
                Action::DelegationPrepare { .. } => {
                    let certificate = self.node.call(
                        json!({"command":"retained_delegation","sign_request":signed}),
                        None,
                    )?;
                    return show(&certificate);
                }
                Action::OpenPrepare { .. } => {
                    println!(
                        "Existing own partial signing request: {}",
                        hex::encode(signed.0)
                    );
                    println!(
                        "Original review: {}",
                        hex::encode(field_id(&v, "review_digest")?.0)
                    );
                    println!("Review the identical reserved terms again under the current native selection?");
                    if !approve()? {
                        return Ok(());
                    }
                }
                _ => {
                    println!("An authorization already exists. Queue that exact signature without signing again?");
                    return if approve()? {
                        self.node.queue(signed)
                    } else {
                        Ok(())
                    };
                }
            }
        }
        self.node.refresh()?;
        let timestamp = self.evaluation_time()?;
        match &mut action {
            Action::OpenPrepare { tip, plan } => {
                *tip = self.node.tip;
                plan.timestamp = timestamp;
            }
            Action::TransferPrepare { tip, plan } => {
                *tip = self.node.tip;
                plan.timestamp = timestamp;
            }
            Action::OnchainPrepare { tip, plan } => {
                *tip = self.node.tip;
                plan.timestamp = timestamp;
            }
            Action::DelegationPrepare { tip, .. } => {
                *tip = self.node.tip;
            }
            _ => return Err("Unsupported retained manual preparation".into()),
        }
        let is_open = matches!(action, Action::OpenPrepare { .. });
        let is_delegation = matches!(action, Action::DelegationPrepare { .. });
        if let Some((signed, response)) = self.review_sign(action, &a)? {
            if is_delegation {
                show(&response["delegation"])?;
            } else if !is_open {
                self.node.queue(signed)?;
            }
        }
        Ok(())
    }
    pub(super) fn fast_menu(&mut self) -> Result<()> {
        loop {
            println!("\nFast payments and native channel custody\n1 Register owner/receipt-service role\n2 Channel balance and pending state\n3 Create and sign fast payment\n4 Review received payment proposal\n5 Resume retained fast review/signature\n6 Send retained invoice\n7 Send retained own signature\n8 Combine signatures and send full receipt\n9 Receipt service: review and acknowledge receipt\n10 Receipt service: send retained acknowledgment\n11 Retain complete payment and inspect onward state\n12 Create joint opening proposal\n13 Review received opening proposal\n14 Send retained opening proposal/partial\n15 Combine opening partials and queue native operation\n16 Native close/challenge/miner-fee claim/settle\n17 Authorize bounded fee wallet and start monitor\n18 Resume existing fee monitor\n19 Stop fee monitor\n20 Runtime status\n21 Resume native opening/action preparation\n0 Back");
            let choice = text("Choose")?;
            let result = match choice.as_str() {
                "0" => return Ok(()),
                "1" => self.register_fast(),
                "2" => (|| {
                    let (actor, _) = self.actor(Some(false))?;
                    let v = self
                        .node
                        .call(json!({"command":"owner_state","actor":actor}), None)?;
                    show(&v)
                })(),
                "3" => self.fast_propose(),
                "4" => self.fast_receive(false),
                "5" => self.fast_resume(),
                "6" => self.fast_send(false),
                "7" => self.fast_send(true),
                "8" => self.fast_combine(),
                "9" => self.fast_receive(true),
                "10" => self.fast_ack(),
                "11" => self.fast_complete(),
                "12" => self.open_channel(),
                "13" => self.receive_opening(),
                "14" => self.send_opening(),
                "15" => self.combine_opening(),
                "16" => self.native_exit(),
                "17" => self.fee_monitor(),
                "18" => self.resume_monitor(),
                "19" => self
                    .node
                    .call(json!({"command":"monitor_stop"}), None)
                    .map(|_| {
                        println!("Monitoring stopped; consent and retained obligations remain.")
                    }),
                "20" => self.node.refresh().and_then(|v| show(&v)),
                "21" => self.resume_native_preparation(),
                _ => Err("Choose a listed action".into()),
            };
            if let Err(e) = result {
                if !self.node.healthy || e == "Input closed" || e.starts_with("Input line too long")
                {
                    return Err(e);
                }
                println!("Action stopped: {e:?}. Original custody, signatures and reservations remain retained.");
            }
        }
    }
}
