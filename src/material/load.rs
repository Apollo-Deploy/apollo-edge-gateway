//! TLS binding validation and loading of verified material from the certificate store.
use std::path::{Component, Path, PathBuf};

use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use sha2::{Digest, Sha256};

use crate::control::EdgeConfiguration;

use super::paths::{canonical_root, validate_regular_material_file};

pub fn validate_configuration(
    material_directory: &Path,
    configuration: &EdgeConfiguration,
) -> anyhow::Result<()> {
    let identity = configuration
        .identity
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("certificate configuration identity is missing"))?;

    for route in &configuration.routes {
        let Some(tls) = route.tls.as_ref() else {
            continue;
        };

        let expected_reference = format!(
            "{}/{}/{}/{}",
            identity.organization_id,
            identity.project_id,
            tls.certificate_id,
            tls.certificate_version
        );

        if tls.certificate_id.is_empty()
            || tls.certificate_version == 0
            || tls.material_reference != expected_reference
        {
            anyhow::bail!("certificate material scope does not match its binding");
        }

        let _ = load_certificate_material(
            material_directory,
            &tls.material_reference,
            &tls.public_certificate_hash,
            &tls.certificate_chain_hash,
        )?;
    }

    Ok(())
}

pub fn load_certificate_material(
    material_directory: &Path,
    material_reference: &str,
    expected_public_key_hash: &[u8],
    expected_chain_hash: &[u8],
) -> anyhow::Result<(X509, Vec<X509>, PKey<Private>)> {
    let root = canonical_root(material_directory)?;

    let mut relative = PathBuf::new();

    for component in Path::new(material_reference).components() {
        match component {
            Component::Normal(value) => relative.push(value),
            _ => anyhow::bail!("certificate material reference is unsafe"),
        }
    }

    if relative.as_os_str().is_empty() {
        anyhow::bail!("certificate material reference is empty");
    }

    let mut directory = root.clone();

    for component in relative.components() {
        let Component::Normal(value) = component else {
            anyhow::bail!("certificate material reference is unsafe");
        };

        directory.push(value);

        let metadata = std::fs::symlink_metadata(&directory)?;

        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            anyhow::bail!("certificate material path contains an unsafe directory");
        }
    }

    let directory = std::fs::canonicalize(directory)?;

    if !directory.starts_with(&root) {
        anyhow::bail!("certificate material escapes its store");
    }

    let certificate_path = directory.join("certificate.pem");

    let private_key_path = directory.join("private-key.pem");

    validate_regular_material_file(&certificate_path, false)?;

    validate_regular_material_file(&private_key_path, true)?;

    let certificate_bytes = std::fs::read(certificate_path)?;

    let mut certificates = X509::stack_from_pem(&certificate_bytes)?.into_iter();

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

    let private_key = PKey::private_key_from_pem(&std::fs::read(private_key_path)?)?;

    if leaf.public_key()?.public_key_to_der()? != private_key.public_key_to_der()? {
        anyhow::bail!("certificate private key does not match Apollo certificate");
    }

    Ok((leaf, chain, private_key))
}
