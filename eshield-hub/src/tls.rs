use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::CertificateDer;
use std::path::Path;
use std::sync::Arc;

pub fn load_rustls_config(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<RustlsConfig> {
    let cert_file = std::fs::File::open(cert_path).context("open TLS certificate")?;
    let cert_reader = &mut std::io::BufReader::new(cert_file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse TLS certificate")?;

    let key_file = std::fs::File::open(key_path).context("open TLS private key")?;
    let key_reader = &mut std::io::BufReader::new(key_file);
    let key = rustls_pemfile::private_key(key_reader)
        .context("parse TLS private key")?
        .context("no private key found")?;

    let config = if let Some(ca_path) = client_ca_path {
        let ca_file = std::fs::File::open(ca_path).context("open client CA")?;
        let ca_reader = &mut std::io::BufReader::new(ca_file);
        let mut roots = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(ca_reader) {
            roots.add(cert?)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder(roots.into())
            .build()
            .context("build client verifier")?;
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
    } else {
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
    }
    .context("build TLS config")?;

    Ok(RustlsConfig::from_config(Arc::new(config)))
}
