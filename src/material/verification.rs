//! Certificate-chain, public-key hash, and private-key checks for incoming material bytes.

use openssl::pkey::PKey;
use openssl::x509::X509;
use sha2::{Digest, Sha256};

pub(super) fn verify_material_bytes(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    expected_public_key_hash: &[u8],
    expected_chain_hash: &[u8],
) -> anyhow::Result<()> {
    let mut certificates = X509::stack_from_pem(certificate_pem)?.into_iter();
    let leaf = certificates
        .next()
        .ok_or_else(|| anyhow::anyhow!("certificate chain is empty"))?;
    let chain: Vec<X509> = certificates.collect();
    let public_key_hash = Sha256::digest(leaf.public_key()?.public_key_to_der()?);
    if public_key_hash.as_slice() != expected_public_key_hash {
        anyhow::bail!("certificate public key hash does not match Apollo state");
    }
    let mut chain_bytes = Vec::new();
    for certificate in std::iter::once(&leaf).chain(chain.iter()) {
        chain_bytes.extend_from_slice(&certificate.to_der()?);
    }
    if Sha256::digest(chain_bytes).as_slice() != expected_chain_hash {
        anyhow::bail!("certificate chain hash does not match Apollo state");
    }
    let private_key = PKey::private_key_from_pem(private_key_pem)?;
    if leaf.public_key()?.public_key_to_der()? != private_key.public_key_to_der()? {
        anyhow::bail!("certificate private key does not match Apollo certificate");
    }
    Ok(())
}
