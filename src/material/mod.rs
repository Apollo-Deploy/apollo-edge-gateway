//! Immutable, tenant-scoped certificate installation, loading, and retirement.
mod cache;
mod install;
mod load;
mod paths;
mod retirement;
mod verification;

pub use cache::CachedCertificate;
pub(crate) use cache::load_configuration;
pub use install::install_certificate_material;
pub use load::{load_certificate_material, validate_configuration};
pub use paths::canonical_root;
pub use retirement::{discover_material_references, remove_certificate_material};
