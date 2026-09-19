use crate::ip::parse_cidr;
use anyhow::{Context, Result};
use eshield_common::IpKey;
use std::collections::HashSet;
use std::path::Path;
use tracing::{debug, warn};

/// 封禁的 CIDR 条目（支持 IPv4/IPv6）。
#[derive(Debug, Clone)]
pub struct GeoIpBlock {
    pub key: IpKey,
    pub prefix: u32,
    pub reason: String,
}

/// 根据配置解析 GeoIP/ASN CSV 并返回需要封禁的 CIDR 列表。
pub fn load_geoip_blocks(config: &crate::config::GeoIpConfig) -> Result<Vec<GeoIpBlock>> {
    load_entries(config, &config.block_countries, &config.block_asns, "block")
}

/// 根据配置解析 GeoIP/ASN CSV 并返回允许放行的 CIDR 列表。
pub fn load_geoip_allows(config: &crate::config::GeoIpConfig) -> Result<Vec<GeoIpBlock>> {
    load_entries(config, &config.allow_countries, &config.allow_asns, "allow")
}

fn load_entries(
    config: &crate::config::GeoIpConfig,
    countries: &[String],
    asns: &[u32],
    kind: &str,
) -> Result<Vec<GeoIpBlock>> {
    let mut blocks = Vec::new();

    let countries: HashSet<String> = countries.iter().map(|s| s.to_ascii_uppercase()).collect();
    let asns: HashSet<u32> = asns.iter().copied().collect();

    if !countries.is_empty() {
        if let Some(path) = &config.country_blocks_csv {
            let path = Path::new(path);
            if path.exists() {
                blocks.extend(parse_country_csv(path, &countries, kind)?);
            } else {
                warn!("country blocks CSV not found: {}", path.display());
            }
        }
    }

    if !asns.is_empty() {
        if let Some(path) = &config.asn_blocks_csv {
            let path = Path::new(path);
            if path.exists() {
                blocks.extend(parse_asn_csv(path, &asns, kind)?);
            } else {
                warn!("ASN blocks CSV not found: {}", path.display());
            }
        }
    }

    debug!(
        "loaded {} GeoIP/ASN {} entries (countries={:?}, asns={:?})",
        blocks.len(),
        kind,
        countries,
        asns,
    );
    Ok(blocks)
}

fn parse_country_csv(
    path: &Path,
    countries: &HashSet<String>,
    kind: &str,
) -> Result<Vec<GeoIpBlock>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(path)
        .with_context(|| format!("open country CSV {}", path.display()))?;

    let mut blocks = Vec::new();
    for result in rdr.records() {
        let record = result?;
        if record.len() < 2 {
            continue;
        }
        let network = record[0].trim();
        let country = record[1].trim().to_ascii_uppercase();
        if !countries.contains(&country) {
            continue;
        }
        match parse_cidr(network) {
            Ok((key, prefix)) => blocks.push(GeoIpBlock {
                key,
                prefix,
                reason: format!("geoip-{}-country-{}", kind, country),
            }),
            Err(e) => warn!("skip invalid CIDR {}: {}", network, e),
        }
    }
    Ok(blocks)
}

fn parse_asn_csv(path: &Path, asns: &HashSet<u32>, kind: &str) -> Result<Vec<GeoIpBlock>> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_path(path)
        .with_context(|| format!("open ASN CSV {}", path.display()))?;

    let mut blocks = Vec::new();
    for result in rdr.records() {
        let record = result?;
        if record.len() < 2 {
            continue;
        }
        let network = record[0].trim();
        let asn: u32 = match record[1].trim().parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        if !asns.contains(&asn) {
            continue;
        }
        match parse_cidr(network) {
            Ok((key, prefix)) => blocks.push(GeoIpBlock {
                key,
                prefix,
                reason: format!("geoip-{}-asn-{}", kind, asn),
            }),
            Err(e) => warn!("skip invalid CIDR {}: {}", network, e),
        }
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GeoIpConfig;
    use std::io::Write;

    #[test]
    fn test_load_country_csv() {
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("country.csv");
        let mut f = std::fs::File::create(&csv).unwrap();
        f.write_all(b"network,country_iso\n10.0.0.0/8,US\n192.168.1.0/24,CN\n")
            .unwrap();

        let mut cfg = GeoIpConfig::default();
        cfg.country_blocks_csv = Some(csv.to_string_lossy().to_string());
        cfg.block_countries = vec!["CN".to_string()];

        let blocks = load_geoip_blocks(&cfg).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].prefix, 24);
        assert!(blocks[0].reason.contains("CN"));
    }

    #[test]
    fn test_load_asn_csv() {
        let dir = tempfile::tempdir().unwrap();
        let csv = dir.path().join("asn.csv");
        let mut f = std::fs::File::create(&csv).unwrap();
        f.write_all(b"network,asn,asn_org\n10.1.0.0/16,12345,Example\n")
            .unwrap();

        let mut cfg = GeoIpConfig::default();
        cfg.asn_blocks_csv = Some(csv.to_string_lossy().to_string());
        cfg.block_asns = vec![12345];

        let blocks = load_geoip_blocks(&cfg).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].prefix, 16);
    }
}
