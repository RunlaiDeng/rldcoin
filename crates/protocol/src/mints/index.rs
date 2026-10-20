//! Pure event/slot correspondence, never ledger finality or issuance authority.
use super::*;
use crate::{codec::Blob, model::Currency, proof::Verifier};
record!(Claim{currency:Id => 0,home:Id => 1,events:Id => 2,slots:Id => 3,count:u64 => 4});
record!(Certificate{claim:Claim => 0,receipt:Blob => 1});
record!(Append{record:MintRecord => 0,event_absence:Absence => 1,slot_absence:Absence => 2});
record!(Witness{currency:Currency => 0,home:Id => 1,predecessor:Option<Certificate> => 2,complete:Option<Vec<MintRecord>> => 3,steps:Vec<Append> => 4});
pub fn journal(c: &Claim) -> Vec<u8> {
    crate::codec::tagged("RLD-MINT-INDEX-CORRESPONDENCE-1", c.currency, c)
}
pub fn verify(currency: &Currency, c: &Certificate) -> Result<()> {
    ensure!(
        c.claim.currency == currency.id()
            && c.claim.count <= u64::from(crate::ROOTS) * u64::from(crate::SLOTS),
        "Mint index currency/count"
    );
    Verifier { currency }.receipt(currency.proof.native_image, &journal(&c.claim), &c.receipt)
}
pub fn execute(w: &Witness) -> Result<Claim> {
    w.currency.validate()?;
    let c = w.currency.id();
    ensure!(w.steps.len() <= 4096, "Mint index append bound");
    let mut claim = match (&w.predecessor, &w.complete) {
        (Some(p), None) => {
            verify(&w.currency, p)?;
            ensure!(p.claim.home == w.home, "Mint index predecessor home");
            p.claim.clone()
        }
        (None, Some(values)) => {
            ensure!(w.steps.is_empty(), "complete Mint index mixed with updates");
            return Mints::from_sorted(c, w.home, values.clone())?.index_claim();
        }
        (None, None) => Mints::new(c, w.home).index_claim()?,
        _ => anyhow::bail!("one Mint index base required"),
    };
    for step in &w.steps {
        Mints::validate(&step.record)?;
        ensure!(
            step.event_absence.count == claim.count && step.slot_absence.count == claim.count,
            "Mint index prior counts"
        );
        let event = step.record.entry(c);
        let slot = Slot {
            root: step.record.root,
            slot: step.record.slot,
            event: step.record.event,
        }
        .entry(c);
        let events = crate::merkle::insert_absent(
            c,
            &format!("{}/mints", w.home),
            claim.events,
            &event,
            &step.event_absence,
        )?;
        let slots = crate::merkle::insert_absent(
            c,
            &format!("{}/mint-slots-aux", w.home),
            claim.slots,
            &slot,
            &step.slot_absence,
        )?;
        let count = claim
            .count
            .checked_add(1)
            .context("Mint index count exhaustion")?;
        ensure!(
            count <= u64::from(crate::ROOTS) * u64::from(crate::SLOTS),
            "Mint index slot budget"
        );
        claim = Claim {
            currency: c,
            home: w.home,
            events,
            slots,
            count,
        };
    }
    Ok(claim)
}
