//! Idempotent installation of immutable certificate versions through private staging.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::control::InstallCertificateMaterialRequest;

use super::load::load_certificate_material;
use super::paths::{canonical_root, ensure_private_directory, safe_material_segment};
use super::verification::verify_material_bytes;

const MAX_CERTIFICATE_PEM_BYTES: usize = 1024 * 1024;

const MAX_PRIVATE_KEY_PEM_BYTES: usize = 64 * 1024;

static NEXT_INSTALL_ID: AtomicU64 = AtomicU64::new(1);

/// Installs one immutable, tenant-scoped certificate version. Repeating the
/// same delivery is idempotent; a version is never overwritten with new bytes.
pub fn install_certificate_material(
    material_directory: &Path,
    request: &InstallCertificateMaterialRequest,
) -> anyhow::Result<bool> {
    if !safe_material_segment(&request.organization_id)
        || !safe_material_segment(&request.project_id)
        || !safe_material_segment(&request.certificate_id)
        || request.certificate_version == 0
        || request.certificate_chain_pem.is_empty()
        || request.certificate_chain_pem.len() > MAX_CERTIFICATE_PEM_BYTES
        || request.private_key_pem.is_empty()
        || request.private_key_pem.len() > MAX_PRIVATE_KEY_PEM_BYTES
        || request.public_key_sha256.len() != 32
        || request.certificate_chain_sha256.len() != 32
    {
        anyhow::bail!("certificate material request is invalid");
    }

    verify_material_bytes(
        &request.certificate_chain_pem,
        &request.private_key_pem,
        &request.public_key_sha256,
        &request.certificate_chain_sha256,
    )?;

    let root = canonical_root(material_directory)?;

    let reference = format!(
        "{}/{}/{}/{}",
        request.organization_id,
        request.project_id,
        request.certificate_id,
        request.certificate_version
    );

    let destination = root.join(&reference);

    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!("certificate version path is unsafe");
            }

            let _ = load_certificate_material(
                &root,
                &reference,
                &request.public_key_sha256,
                &request.certificate_chain_sha256,
            )?;

            return Ok(false);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let mut parent = root.clone();

    for component in [
        request.organization_id.as_str(),
        request.project_id.as_str(),
        request.certificate_id.as_str(),
    ] {
        parent = ensure_private_directory(&parent, component)?;
    }

    let stage = loop {
        let id = NEXT_INSTALL_ID.fetch_add(1, Ordering::Relaxed);

        let path = parent.join(format!(".install-{}-{id}", std::process::id()));

        match fs::create_dir(&path) {
            Ok(()) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    };

    #[cfg(unix)]
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;

    let write_result = (|| -> anyhow::Result<()> {
        write_material_file(
            &stage.join("certificate.pem"),
            &request.certificate_chain_pem,
        )?;

        write_material_file(&stage.join("private-key.pem"), &request.private_key_pem)?;

        File::open(&stage)?.sync_all()?;

        fs::rename(&stage, &destination)?;

        File::open(&parent)?.sync_all()?;

        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_dir_all(&stage);

        if let Ok(metadata) = fs::symlink_metadata(&destination)
            && !metadata.file_type().is_symlink()
            && metadata.is_dir()
        {
            let _ = load_certificate_material(
                &root,
                &reference,
                &request.public_key_sha256,
                &request.certificate_chain_sha256,
            )?;

            return Ok(false);
        }

        return Err(error);
    }

    let _ = load_certificate_material(
        &root,
        &reference,
        &request.public_key_sha256,
        &request.certificate_chain_sha256,
    )?;

    Ok(true)
}

fn write_material_file(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();

    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        options.mode(0o600);
    }

    let mut file = options.open(path)?;

    file.write_all(contents)?;

    file.sync_all()?;

    Ok(())
}
