//! Admission-time TLS objects. The request path never reads the material store.
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use openssl::asn1::Asn1Time;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::{X509CheckFlags, X509VerifyFlags, X509VerifyParam};
use openssl::x509::{X509, X509StoreContext};

use super::{load_certificate_material, validate_configuration};
use crate::control::EdgeConfiguration;

pub struct CachedCertificate {
    pub leaf: X509,
    pub chain: Vec<X509>,
    pub private_key: PKey<Private>,
    not_before: i64,
    not_after: i64,
}

impl CachedCertificate {
    pub fn is_valid_now(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|t| t.as_secs().min(i64::MAX as u64) as i64)
            .unwrap_or(0);

        self.not_before <= now && now < self.not_after
    }
}

pub(crate) fn load_configuration(
    root: &Path,
    configuration: &EdgeConfiguration,
) -> anyhow::Result<BTreeMap<String, Arc<CachedCertificate>>> {
    validate_configuration(root, configuration)?;

    let mut by_host = BTreeMap::new();

    let mut by_reference = BTreeMap::new();

    for route in &configuration.routes {
        let Some(binding) = &route.tls else {
            continue;
        };

        let material = if let Some(material) = by_reference.get(&binding.material_reference) {
            Arc::clone(material)
        } else {
            let (leaf, chain, private_key) = load_certificate_material(
                root,
                &binding.material_reference,
                &binding.public_certificate_hash,
                &binding.certificate_chain_hash,
            )?;

            let epoch = Asn1Time::from_unix(0)?;

            let from = epoch.diff(leaf.not_before())?;

            let until = epoch.diff(leaf.not_after())?;

            let material = Arc::new(CachedCertificate {
                leaf,
                chain,
                private_key,
                not_before: i64::from(from.days) * 86_400 + i64::from(from.secs),
                not_after: i64::from(until.days) * 86_400 + i64::from(until.secs),
            });

            anyhow::ensure!(
                material.is_valid_now(),
                "certificate is not currently valid"
            );

            by_reference.insert(binding.material_reference.clone(), Arc::clone(&material));

            material
        };

        // Trust is supplied by the authenticated controller's pinned hashes. Use
        // OpenSSL for SAN matching and validity, including its wildcard rules.
        let mut parameters = X509VerifyParam::new()?;

        parameters.set_hostflags(
            X509CheckFlags::NEVER_CHECK_SUBJECT | X509CheckFlags::NO_PARTIAL_WILDCARDS,
        );

        parameters.set_host(&route.hostname)?;

        let mut store = X509StoreBuilder::new()?;

        store.add_cert(material.leaf.clone())?;

        store.set_flags(X509VerifyFlags::PARTIAL_CHAIN)?;

        store.set_param(&parameters)?;

        let chain = Stack::new()?;

        let valid =
            X509StoreContext::new()?.init(&store.build(), &material.leaf, &chain, |ctx| {
                ctx.verify_cert()
            })?;

        anyhow::ensure!(valid, "certificate does not cover route hostname");

        // Preserve the existing first-binding selection for routes sharing SNI
        // but using different path matches. Every binding is still validated.
        by_host.entry(route.hostname.clone()).or_insert(material);
    }

    Ok(by_host)
}
