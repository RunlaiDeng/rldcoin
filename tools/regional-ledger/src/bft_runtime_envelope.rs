//! Exact private Runtime dispatch. Parsed bodies and byte references grant no
//! Native authority; each use retains its profile's complete verification.
use crate::{
    bft_client, bft_network as net, bft_onward_network as onward, bft_runtime_archive::Header,
    require, storage::Store, Hash, Result,
};
use serde_json::Value;

pub(crate) fn require_profile(format: &str, node: &Store) -> Result<()> {
    let rules = &node.trust.region(node.chain.region)?.rules;
    if format == bft_client::ONWARD_FORMAT {
        require(
            rules == crate::paged_bft::ONWARD_NETWORK_RULES,
            "onward Runtime requires its exact signed admission",
        )?;
        node.require_onward_network_state()?;
        node.check_onward_network_safety()
    } else {
        crate::paged_bft::require_runtime_adoption(rules)
    }
}

pub(crate) enum Wire {
    Existing(Box<net::WireEnvelope>),
    Onward(Box<onward::WireEnvelope>),
}
impl Wire {
    pub(crate) fn decode(value: Value, runtime: &str) -> Result<Self> {
        let wire = if runtime == bft_client::ONWARD_FORMAT {
            require(
                value["format"] == onward::FORMAT && value.get("history").is_some(),
                "onward Runtime envelope format/history differs",
            )?;
            Self::Onward(Box::new(
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?,
            ))
        } else {
            require(
                value["format"] == net::FORMAT || value["format"] == net::ORIGIN_FORMAT,
                "existing Runtime envelope format differs",
            )?;
            Self::Existing(Box::new(
                serde_json::from_value(value.clone()).map_err(|e| e.to_string())?,
            ))
        };
        require(
            wire.wire_value()? == value,
            "Runtime envelope loses typed fields",
        )?;
        Ok(wire)
    }
    pub(crate) fn bytes(raw: &[u8], runtime: &str) -> Result<Self> {
        Self::decode(
            crate::wallet_http::decode_unique_with_limit(raw, crate::contact::MAX_PAYLOAD)?,
            runtime,
        )
    }
    pub(crate) fn local(body: net::Body, node: &Store, runtime: &str) -> Result<Self> {
        require_profile(runtime, node)?;
        if runtime == bft_client::ONWARD_FORMAT {
            Ok(Self::Onward(Box::new(onward::local_envelope(body, node)?)))
        } else {
            Ok(Self::Existing(Box::new(
                net::local_envelope(body, node)?.envelope,
            )))
        }
    }
    pub(crate) fn wire_value(&self) -> Result<Value> {
        match self {
            Self::Existing(w) => serde_json::to_value(w),
            Self::Onward(w) => serde_json::to_value(w),
        }
        .map_err(|e| e.to_string())
    }
    pub(crate) fn body(&self) -> &net::Body {
        match self {
            Self::Existing(w) => &w.body,
            Self::Onward(w) => &w.body,
        }
    }
    pub(crate) fn header(&self) -> Header {
        match self {
            Self::Existing(w) => Header {
                format: w.format.clone(),
                currency: w.currency,
                region: w.region,
            },
            Self::Onward(w) => Header {
                format: w.format.clone(),
                currency: w.currency,
                region: w.region,
            },
        }
    }
    pub(crate) fn verify(&self, node: &Store) -> Result<Option<Hash>> {
        match self {
            Self::Existing(w) => {
                w.as_ref().clone().expand()?.verify(node)?;
            }
            Self::Onward(w) => {
                w.as_ref().clone().expand()?.verify(node)?;
            }
        }
        self.body().checkpoint_value()
    }
    pub(crate) fn sync(&self, node: &mut Store) -> Result<()> {
        match self {
            Self::Onward(w) => onward::sync_envelope(node, w.as_ref().clone()),
            Self::Existing(w) => {
                let envelope = w.as_ref().clone().expand()?;
                envelope.verify(node)?;
                if w.format == net::ORIGIN_FORMAT {
                    net::sync_origin_envelope(node, w.as_ref().clone())
                } else {
                    net::sync(node, envelope.evidence)
                }
            }
        }
    }
    pub(crate) fn verify_cold(&self, node: &Store) -> Result<Option<Hash>> {
        let value = self.verify(node)?;
        if let Self::Onward(w) = self {
            let envelope = w.as_ref().clone().expand()?;
            let mut snapshots = envelope.evidence.snapshots;
            if let net::Body::Finalized(s) = envelope.body {
                snapshots.push(*s);
            }
            node.require_retained_onward_material(envelope.history.as_ref(), &snapshots)?;
        }
        Ok(value)
    }
}
