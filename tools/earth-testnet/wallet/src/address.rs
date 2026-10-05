use anyhow::{anyhow, ensure, Result};
use sha2::{Digest, Sha256};

/// An error-detecting, network-bound address; it does not authenticate a person.
pub fn encode(chain: &str, public: &str) -> Result<String> {
    rld_core::AdmissionHash32::from_hex(chain).map_err(|e| anyhow!(e))?;
    rld_core::validate_ed25519_public_key(public).map_err(|e| anyhow!(e))?;
    ensure!(
        chain == chain.to_ascii_lowercase() && public == public.to_ascii_lowercase(),
        "地址必须使用小写编码"
    );
    let body = format!("rld:{chain}:{public}");
    let checksum = hex::encode(Sha256::digest(format!("RLD-ADDRESS-V1\0{body}").as_bytes()));
    Ok(format!("{body}:{}", &checksum[..12]))
}

pub fn decode(chain: &str, address: &str) -> Result<String> {
    if !address.starts_with("rld:") {
        rld_core::validate_ed25519_public_key(address).map_err(|e| anyhow!(e))?;
        ensure!(
            address == address.to_ascii_lowercase(),
            "公钥必须使用小写编码"
        );
        return Ok(address.into());
    }
    let parts: Vec<_> = address.split(':').collect();
    ensure!(
        parts.len() == 4 && parts[1] == chain,
        "收款地址属于另一条链，或格式不完整"
    );
    ensure!(
        encode(chain, parts[2])? == address,
        "地址校验失败；请重新向收款人获取完整地址"
    );
    Ok(parts[2].into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_typo_network_and_noncanonical_address() {
        let public = rld_core::generate_identity().public_key;
        let a = encode(crate::CHAIN, &public).unwrap();
        assert_eq!(decode(crate::CHAIN, &a).unwrap(), public);
        assert_eq!(decode(crate::CHAIN, &public).unwrap(), public);
        assert!(decode(&"12".repeat(32), &a).is_err());
        let mut b = a.clone();
        b.pop();
        b.push(if a.ends_with('0') { '1' } else { '0' });
        assert!(decode(crate::CHAIN, &b).is_err());
        assert!(decode(crate::CHAIN, &a.to_ascii_uppercase()).is_err());
        assert!(decode(crate::CHAIN, &format!("{a}:ignored")).is_err());
    }
}
