//! Exact typed snapshot context sharing, not root/ledger adoption. No dictionary
//! references, peer cache, truncation or generic decompression is involved.
use crate::object_store::Object;
use anyhow::{Result, ensure};
use rld_protocol::{
    codec::{Blob, Id, decode, encode},
    record,
};
const FORMAT: &str = "RLD-NATIVE-DISK-OBSERVATION-5";
// Fixed order: applied, five permanent maps, outputs, both Mint indexes,
// definitions, services, coupon uses and receiving families.
const KINDS: [(&str, Option<&str>); 14] = [
    ("RLD-APPLIED-DISK-1", None),
    ("RLD-PERMANENT-DISK-1", Some("births")),
    ("RLD-PERMANENT-DISK-1", Some("decisions")),
    ("RLD-PERMANENT-DISK-1", Some("redemptions")),
    ("RLD-PERMANENT-DISK-1", Some("resolutions")),
    ("RLD-PERMANENT-DISK-1", Some("funding")),
    ("RLD-UTXO-DISK-1", None),
    ("RLD-MINT-EVENT-PATH-1", None),
    ("RLD-MINT-SLOT-PATH-1", None),
    ("RLD-COVER-PATH-1", None),
    ("RLD-FEE-POLICY-PATH-1", None),
    ("RLD-SERVICE-PATH-1", None),
    ("RLD-COUPON-USE-PATH-1", None),
    ("RLD-FAMILY-PATH-1", None),
];
record!(Link{object:Object => 0,native:Id => 1,count:u64 => 2,first:Id => 3,last:Id => 4,height:u8 => 5,depth:u16 => 6});
record!(Plain{format:String => 0,currency:Id => 1,domain:Id => 2,genesis:Id => 3,root:Option<Link> => 4});
record!(Tagged{format:String => 0,currency:Id => 1,domain:Id => 2,genesis:Id => 3,root:Option<Link> => 4,tag:String => 5});
record!(Packed{format:String => 0,currency:Id => 1,domain:Id => 2,genesis:Id => 3,roots:Vec<Option<Link>> => 4});
record!(MintPair{format:String => 0,events:Blob => 1,slots:Blob => 2});

pub(crate) fn split_mints(bytes: &[u8]) -> Result<[Vec<u8>; 2]> {
    let p: MintPair = decode(bytes, 2048)?;
    ensure!(
        p.format == "RLD-MINT-FACTS-DISK-1",
        "observation Mint pair format"
    );
    Ok([p.events.0, p.slots.0])
}
pub(crate) fn join_mints(events: Vec<u8>, slots: Vec<u8>) -> Vec<u8> {
    encode(&MintPair {
        format: "RLD-MINT-FACTS-DISK-1".into(),
        events: Blob(events),
        slots: Blob(slots),
    })
}
pub(crate) fn pack(snapshots: [Vec<u8>; 14]) -> Result<Vec<u8>> {
    let mut context = None;
    let mut roots = Vec::with_capacity(KINDS.len());
    for ((format, name), bytes) in KINDS.iter().zip(snapshots) {
        let p = if let Some(name) = name {
            let t: Tagged = decode(&bytes, 4096)?;
            ensure!(
                t.tag == format!("{}/{name}", t.domain),
                "observation exact map tag"
            );
            Plain {
                format: t.format,
                currency: t.currency,
                domain: t.domain,
                genesis: t.genesis,
                root: t.root,
            }
        } else {
            decode::<Plain>(&bytes, 4096)?
        };
        ensure!(p.format == *format, "observation storage kind");
        let c = (p.currency, p.domain, p.genesis);
        if let Some(old) = context {
            ensure!(c == old, "observation shared context mismatch");
        } else {
            context = Some(c);
        }
        roots.push(p.root);
    }
    let (currency, domain, genesis) = context.expect("fixed nonempty inventory");
    let bytes = encode(&Packed {
        format: FORMAT.into(),
        currency,
        domain,
        genesis,
        roots,
    });
    ensure!(bytes.len() <= 4096, "native disk observation bound");
    Ok(bytes)
}
pub(crate) fn unpack(bytes: &[u8]) -> Result<[Vec<u8>; 14]> {
    let p: Packed = decode(bytes, 4096)?;
    ensure!(
        p.format == FORMAT && p.roots.len() == KINDS.len(),
        "observation format/inventory"
    );
    let mut out = Vec::with_capacity(KINDS.len());
    for ((format, name), root) in KINDS.iter().zip(p.roots) {
        out.push(if let Some(name) = name {
            encode(&Tagged {
                format: (*format).into(),
                currency: p.currency,
                domain: p.domain,
                genesis: p.genesis,
                root,
                tag: format!("{}/{name}", p.domain),
            })
        } else {
            encode(&Plain {
                format: (*format).into(),
                currency: p.currency,
                domain: p.domain,
                genesis: p.genesis,
                root,
            })
        });
    }
    out.try_into()
        .map_err(|_| anyhow::anyhow!("observation inventory"))
}
