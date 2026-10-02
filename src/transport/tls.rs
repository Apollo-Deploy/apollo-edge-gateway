use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use openssl::x509::X509;

use super::server::ControlConfig;

pub(super) fn build_acceptor(config: &ControlConfig) -> anyhow::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls_server())?;
    builder.set_certificate_chain_file(&config.certificate)?;
    builder.set_private_key_file(&config.private_key, SslFiletype::PEM)?;
    builder.set_ca_file(&config.ca_certificate)?;
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    builder.set_session_id_context(b"apollo-edge-control")?;
    builder.check_private_key()?;
    Ok(builder.build())
}

pub(super) fn authorize_peer(certificate: Option<X509>, gateway_id: &str) -> anyhow::Result<()> {
    let certificate =
        certificate.ok_or_else(|| anyhow::anyhow!("control peer certificate missing"))?;
    let common_name = certificate
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .ok_or_else(|| anyhow::anyhow!("control peer identity missing"))?
        .data()
        .to_string()?;
    if common_name != gateway_id {
        return Err(anyhow::anyhow!("control peer identity is not authorized"));
    }
    Ok(())
}
