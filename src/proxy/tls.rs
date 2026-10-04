//! TLS certificate selection and handshake metadata for request SNI validation.
use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::Result;
use pingora::listeners::tls::TlsSettings;
use pingora::listeners::{TlsAccept, TlsAcceptCallbacks};
use pingora::protocols::tls::TlsRef;
use pingora::tls::ext::{ssl_add_chain_cert, ssl_use_certificate, ssl_use_private_key};
use pingora::tls::ssl::NameType;

use crate::GatewayState;

#[derive(Debug)]
pub(super) struct TlsMetadata {
    pub(super) sni: String,
}

struct GatewayTlsCallbacks {
    state: Arc<GatewayState>,
}

/// Creates callback-backed listener TLS settings with HTTP/2 enabled.
///
/// # Errors
///
/// Returns the Pingora error if TLS settings cannot be initialized.
pub(crate) fn tls_settings(
    state: Arc<GatewayState>,
    _material_directory: PathBuf,
) -> Result<TlsSettings> {
    let callbacks: TlsAcceptCallbacks = Box::new(GatewayTlsCallbacks { state });

    let mut tls = TlsSettings::with_callbacks(callbacks)?;

    tls.enable_h2();

    Ok(tls)
}

#[async_trait]
impl TlsAccept for GatewayTlsCallbacks {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let loaded = (|| -> anyhow::Result<()> {
            let host = ssl
                .servername(NameType::HOST_NAME)
                .ok_or_else(|| anyhow::anyhow!("TLS SNI is missing"))?;

            let material = self
                .state
                .certificate_for_host(host)
                .ok_or_else(|| anyhow::anyhow!("no admitted certificate for TLS hostname"))?;

            ssl_use_certificate(ssl, &material.leaf)?;

            for certificate in &material.chain {
                ssl_add_chain_cert(ssl, certificate)?;
            }

            ssl_use_private_key(ssl, &material.private_key)?;

            Ok(())
        })();

        if let Err(error) = loaded {
            eprintln!("Apollo Edge TLS certificate material could not be loaded: {error:#}");
        }
    }

    async fn handshake_complete_callback(
        &self,
        ssl: &TlsRef,
    ) -> Option<Arc<dyn Any + Send + Sync>> {
        Some(Arc::new(TlsMetadata {
            sni: ssl.servername(NameType::HOST_NAME)?.to_owned(),
        }))
    }
}
