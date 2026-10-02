//! Bounded discovery and durable removal of retired certificate versions.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::path::Path;

use super::paths::{ensure_existing_private_directory, safe_material_segment};

const MAX_MATERIAL_VERSIONS: usize = 8_192;

pub fn discover_material_references(root: &Path) -> anyhow::Result<BTreeSet<String>> {
    let mut references = BTreeSet::new();
    let mut visited_directories = 0usize;
    let mut pending = vec![(root.to_path_buf(), Vec::<String>::new())];
    while let Some((parent, components)) = pending.pop() {
        for entry in fs::read_dir(parent)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str().filter(|name| safe_material_segment(name)) else {
                continue;
            };
            let file_type = entry.file_type()?;
            if file_type.is_symlink() || !file_type.is_dir() {
                continue;
            }
            visited_directories += 1;
            if visited_directories > MAX_MATERIAL_VERSIONS * 4 {
                anyhow::bail!("certificate material store exceeds the cleanup bound");
            }
            let mut reference_components = components.clone();
            reference_components.push(name.to_owned());
            if reference_components.len() == 4 {
                let version = reference_components[3]
                    .parse::<u64>()
                    .ok()
                    .filter(|version| *version > 0);
                if version.is_some_and(|version| version.to_string() == reference_components[3]) {
                    references.insert(reference_components.join("/"));
                    if references.len() > MAX_MATERIAL_VERSIONS {
                        anyhow::bail!("certificate material store exceeds the cleanup bound");
                    }
                }
            } else {
                pending.push((entry.path(), reference_components));
            }
        }
    }
    Ok(references)
}

pub fn remove_certificate_material(root: &Path, reference: &str) -> anyhow::Result<()> {
    let mut components = reference.split('/');
    let Some(organization) = components.next() else {
        anyhow::bail!("certificate material reference is invalid");
    };
    let Some(project) = components.next() else {
        anyhow::bail!("certificate material reference is invalid");
    };
    let Some(certificate) = components.next() else {
        anyhow::bail!("certificate material reference is invalid");
    };
    let Some(version) = components.next() else {
        anyhow::bail!("certificate material reference is invalid");
    };
    let version_number = version.parse::<u64>().ok();
    if components.next().is_some()
        || !safe_material_segment(organization)
        || !safe_material_segment(project)
        || !safe_material_segment(certificate)
        || version_number.filter(|value| *value > 0).is_none()
        || version_number.is_some_and(|value| value.to_string() != version)
    {
        anyhow::bail!("certificate material reference is invalid");
    }
    let mut parent = root.to_path_buf();
    for segment in [organization, project, certificate] {
        parent = ensure_existing_private_directory(&parent, segment)?;
    }
    let path = parent.join(version);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            anyhow::bail!("certificate version path is unsafe");
        }
        Ok(_) => {}
    }
    fs::remove_dir_all(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
