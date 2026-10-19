//! Private encrypted key creation and bounded native wallet observations.
use super::*;
use std::collections::BTreeSet;

impl Session {
    fn wallet_key_path(&self, name: &str) -> Result<PathBuf> {
        ensure(
            (1..=64).contains(&name.len())
                && name.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'
                }),
            "INVALID wallet key name",
        )?;
        Ok(self.root.join("keys").join(format!("{name}.key")))
    }
    /// Create a fresh encrypted native key. Existing files are never replaced;
    /// lost replies are recovered by authenticating that file with key_info.
    pub fn wallet_create_key(
        &mut self,
        expected: Hash,
        name: &str,
        password: &[u8],
        now: u64,
    ) -> Result<Value> {
        self.status(expected, now)?;
        let path = self.wallet_key_path(name)?;
        Self::paths(&self.root)?;
        let dir = path.parent().unwrap();
        let mut create = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            create.mode(0o700);
        }
        match create.create(dir) {
            Ok(()) => sync_dir(&self.root)?,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(fast_retainer::io(e)),
        }
        fast_retainer::private(dir, false)?;
        let mut count = 0;
        for entry in fs::read_dir(dir).map_err(fast_retainer::io)? {
            entry.map_err(fast_retainer::io)?;
            count += 1;
            ensure(count < 64, "RESOURCE_WAIT wallet key directory capacity")?;
        }
        ensure(
            !path.try_exists().map_err(fast_retainer::io)?,
            "CONFLICT wallet key already exists",
        )?;
        let key = keyfile::generate()?;
        let owner = Id(key.verifying_key().to_bytes());
        write_new(&path, &keyfile::encrypt(&key, self.chain, password)?)?;
        let mut out = self.wallet_key_info(expected, name, password, now)?;
        ensure(
            out["owner"] == json!(owner),
            "INVALID wallet key readback owner",
        )?;
        out["key_created"] = true.into();
        Ok(out)
    }
    /// Authenticate the retained encrypted file without signing or creating a key.
    pub fn wallet_key_info(
        &mut self,
        expected: Hash,
        name: &str,
        password: &[u8],
        now: u64,
    ) -> Result<Value> {
        let mut out = self.status(expected, now)?;
        let path = self.wallet_key_path(name)?;
        fast_retainer::private(path.parent().unwrap(), false)?;
        let key = load_key_profile(&path, self.chain, Some(password), true)?;
        out["owner"] = json!(Id(key.verifying_key().to_bytes()));
        out["key_name"] = name.into();
        out["key_file"] = path.to_string_lossy().into_owned().into();
        out["key_created"] = false.into();
        out["wallet_key_loaded"] = true.into();
        out["encrypted"] = true.into();
        out["owner_spend_authorized"] = false.into();
        out["key_material_returned"] = false.into();
        self.status(expected, now)?;
        Ok(out)
    }
    /// Discover this owner's selected native outputs without loading a key or
    /// granting spending rights. Reservations are local to this exact caller.
    pub fn native_wallet(
        &mut self,
        expected: Hash,
        owner: Id,
        after: Option<&str>,
        limit: u16,
        now: u64,
    ) -> Result<Value> {
        ensure(
            crate::kernel::valid_point(owner.0),
            "INVALID native wallet owner",
        )?;
        ensure(
            (1..=16).contains(&limit),
            "RESOURCE_WAIT native wallet page bound",
        )?;
        let after = after
            .map(|s| -> Result<Vec<u8>> {
                let raw = bytes(s, 34)?;
                ensure(raw.len() == 34, "INVALID native wallet cursor size")?;
                Ok(raw)
            })
            .transpose()?;
        let mut out = self.status(expected, now)?;
        let mut prepared = BTreeSet::new();
        for op in &self.caller.ops {
            if op.done.as_ref().is_some_and(|d| d.review.is_some()) {
                if let Some((_, plan)) = op.intent.action.preparation() {
                    prepared.extend(plan.inputs()?);
                }
            }
        }
        let mut policy = BTreeSet::new();
        for (_, state) in self.policy_families(self.caller.ops.len())? {
            policy.extend(state.family);
        }
        let ledger = self.native.as_ref().unwrap().ledger();
        let next = ledger
            .tip()
            .height()
            .checked_add(1)
            .ok_or("RESOURCE_WAIT native wallet next height")?;
        let mut totals = [0u128; 5];
        let mut count = 0usize;
        let mut rows = Vec::new();
        let mut last = None;
        let mut more = false;
        for (reference, coin) in ledger.coins() {
            if coin.owner != owner.0 {
                continue;
            }
            count += 1;
            let mature = coin.maturity <= next;
            let preparation_reserved = prepared.contains(reference);
            let policy_reserved = policy.contains(reference);
            let reserved = preparation_reserved || policy_reserved;
            for (index, include) in [true, mature, !mature, reserved, mature && !reserved]
                .into_iter()
                .enumerate()
            {
                if include {
                    totals[index] = totals[index]
                        .checked_add(coin.amount)
                        .ok_or("INVALID native wallet amount sum")?;
                }
            }
            if after.as_ref().is_some_and(|a| reference <= a) {
                continue;
            }
            if rows.len() == usize::from(limit) {
                more = true;
                continue;
            }
            let encoded = hex::encode(reference);
            rows.push(json!({"reference":encoded,"amount":coin.amount.to_string(),
                "maturity_height":coin.maturity.to_string(),"mature_for_next_block":mature,
                "reserved_by_preparation":preparation_reserved,"reserved_by_fee_policy":policy_reserved,
                "manual_input_candidate":mature && !reserved}));
            last = Some(encoded);
        }
        out["owner"] = json!(owner);
        out["amount_unit"] = "runlai".into();
        out["fast_balances_included"] = false.into();
        out["selected_timestamp"] = ledger.tip().timestamp().to_string().into();
        out["next_block_height"] = next.to_string().into();
        out["native_total"] = totals[0].to_string().into();
        out["mature_for_next_block_total"] = totals[1].to_string().into();
        out["immature_total"] = totals[2].to_string().into();
        out["locally_reserved_total"] = totals[3].to_string().into();
        out["mature_locally_unreserved_total"] = totals[4].to_string().into();
        out["owned_output_count"] = count.to_string().into();
        out["page_count"] = rows.len().to_string().into();
        out["outputs"] = rows.into();
        out["next_cursor"] = if more { json!(last) } else { Value::Null };
        out["reservation_scope"] = "THIS_CALLER_ONLY".into();
        out["other_wallet_reservations_known"] = false.into();
        out["manual_candidates_require_review"] = true.into();
        out["observation_only"] = true.into();
        out["owner_spend_authorized"] = false.into();
        out["wallet_key_loaded"] = false.into();
        self.status(expected, now)?;
        Ok(out)
    }
}
