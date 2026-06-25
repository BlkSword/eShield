use anyhow::Context;
use eshield_common::IpKey;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 将 IpKey 格式化为可读的 IPv4/IPv6 字符串。
pub fn format_ip_key(key: &IpKey) -> String {
    match key.family() {
        Some(eshield_common::IpFamily::Ipv4) => {
            Ipv4Addr::from(key.ipv4().to_be_bytes()).to_string()
        }
        Some(eshield_common::IpFamily::Ipv6) => Ipv6Addr::from(key.addr).to_string(),
        _ => format!("unknown(family={})", key.family),
    }
}

/// 将字符串解析为 IpKey（支持 IPv4/IPv6）。
pub fn parse_ip(s: &str) -> anyhow::Result<IpKey> {
    let addr: IpAddr = s.parse().context("invalid IP address")?;
    match addr {
        IpAddr::V4(v4) => Ok(IpKey::from_ipv4(v4.octets())),
        IpAddr::V6(v6) => Ok(IpKey::from_ipv6(v6.octets())),
    }
}

/// 将 IP 或 /32（IPv4）/128（IPv6）CIDR 解析为 IpKey。
/// 用于黑名单等需要精确主机的场景。
pub fn parse_ip_or_cidr(s: &str) -> anyhow::Result<IpKey> {
    if let Ok(key) = parse_ip(s) {
        return Ok(key);
    }
    let (key, prefix) = parse_cidr(s)?;
    let expected = match key.family() {
        Some(eshield_common::IpFamily::Ipv4) => 32,
        Some(eshield_common::IpFamily::Ipv6) => 128,
        None => anyhow::bail!("unknown IP family"),
    };
    if prefix != expected {
        anyhow::bail!(
            "exact host address required; use plain IP or /{}",
            expected
        );
    }
    Ok(key)
}

/// 将 CIDR 字符串解析为 (IpKey, prefix)，支持 IPv4/IPv6。
pub fn parse_cidr(s: &str) -> anyhow::Result<(IpKey, u32)> {
    let parts: Vec<&str> = s.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid CIDR: {}", s);
    }
    let addr: IpAddr = parts[0].parse().context("invalid IP address")?;
    let prefix: u32 = parts[1].parse().context("invalid prefix length")?;

    match addr {
        IpAddr::V4(v4) => {
            if prefix > 32 {
                anyhow::bail!("invalid IPv4 prefix length: {}", prefix);
            }
            let addr = u32::from_be_bytes(v4.octets());
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            Ok((IpKey::from_ipv4((addr & mask).to_be_bytes()), prefix))
        }
        IpAddr::V6(v6) => {
            if prefix > 128 {
                anyhow::bail!("invalid IPv6 prefix length: {}", prefix);
            }
            let mut addr = v6.octets();
            if prefix == 0 {
                addr.fill(0);
            } else {
                let byte = (prefix / 8) as usize;
                let bit = (prefix % 8) as u8;
                if bit > 0 {
                    let mask = 0xffu8 << (8 - bit);
                    addr[byte] &= mask;
                }
                for octet in addr.iter_mut().skip(byte + 1) {
                    *octet = 0;
                }
            }
            Ok((IpKey::from_ipv6(addr), prefix))
        }
    }
}
