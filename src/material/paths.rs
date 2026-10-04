//! Store-root, tenant-segment, and filesystem safety checks shared by material operations.
use std::fs::{self, File};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub fn canonical_root(path: &Path) -> anyhow::Result<PathBuf> {
    let root = std::fs::canonicalize(path)?;

    if !root.is_dir() {
        anyhow::bail!("certificate material store is not a directory");
    }

    Ok(root)
}

pub(super) fn safe_material_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(super) fn ensure_private_directory(parent: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let path = parent.join(name);

    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                anyhow::bail!("certificate material directory is unsafe");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&path)?;

            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;

            File::open(parent)?.sync_all()?;
        }
        Err(error) => return Err(error.into()),
    }

    Ok(path)
}

pub(super) fn ensure_existing_private_directory(
    parent: &Path,
    name: &str,
) -> anyhow::Result<PathBuf> {
    let path = parent.join(name);

    let metadata = fs::symlink_metadata(&path)?;

    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!("certificate material directory is unsafe");
    }

    Ok(path)
}

pub(super) fn validate_regular_material_file(path: &Path, private: bool) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;

    let limit = if private { 64 * 1024 } else { 1024 * 1024 };

    if metadata.len() == 0 || metadata.len() > limit {
        anyhow::bail!("certificate material file size exceeds its bound");
    }

    if !metadata.file_type().is_file() {
        anyhow::bail!("certificate material file is not regular");
    }

    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & 0o777;

        if private && mode != 0o600 {
            anyhow::bail!("private certificate material must be mode 600");
        }

        if !private && mode & 0o022 != 0 {
            anyhow::bail!("certificate material is writable by group or other");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {

    use super::safe_material_segment;

    #[test]
    fn material_segments_enforce_character_and_length_bounds() {
        assert!(safe_material_segment("Org_01-project"));

        assert!(safe_material_segment(&"a".repeat(128)));

        assert!(!safe_material_segment(&"a".repeat(129)));

        for segment in [
            "",
            ".",
            "..",
            "org/project",
            "org\\project",
            "org.name",
            "café",
        ] {
            assert!(!safe_material_segment(segment), "{segment:?}");
        }
    }
}
