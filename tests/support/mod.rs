use apollo_edge_gateway::control::*;
use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{BasicConstraints, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509, X509NameBuilder};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Pki {
    pub ca: X509,
    pub key: PKey<Private>,
}

impl Pki {
    pub fn new() -> Self {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();

        name.append_entry_by_text("CN", "integration CA").unwrap();

        let name = name.build();

        let mut builder = X509::builder().unwrap();

        builder.set_version(2).unwrap();

        builder
            .set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(1).unwrap()).unwrap())
            .unwrap();

        builder.set_subject_name(&name).unwrap();

        builder.set_issuer_name(&name).unwrap();

        builder.set_pubkey(&key).unwrap();

        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();

        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();

        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();

        builder
            .append_extension(KeyUsage::new().key_cert_sign().crl_sign().build().unwrap())
            .unwrap();

        builder.sign(&key, MessageDigest::sha256()).unwrap();

        Self {
            ca: builder.build(),
            key,
        }
    }

    pub fn leaf(&self, host: &str, serial: u32) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();

        let mut name = X509NameBuilder::new().unwrap();

        name.append_entry_by_text("CN", host).unwrap();

        let mut b = X509::builder().unwrap();

        b.set_version(2).unwrap();

        b.set_serial_number(&Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap())
            .unwrap();

        b.set_subject_name(&name.build()).unwrap();

        b.set_issuer_name(self.ca.subject_name()).unwrap();

        b.set_pubkey(&key).unwrap();

        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();

        b.set_not_after(&Asn1Time::days_from_now(10).unwrap())
            .unwrap();

        b.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();

        let san = SubjectAlternativeName::new()
            .dns(host)
            .build(&b.x509v3_context(Some(&self.ca), None))
            .unwrap();

        b.append_extension(san).unwrap();

        b.sign(&self.key, MessageDigest::sha256()).unwrap();

        (b.build(), key)
    }

    pub fn write_control(&self, root: &Path) {
        let (cert, key) = self.leaf("gateway-test", 10);

        fs::write(root.join("ca.pem"), self.ca.to_pem().unwrap()).unwrap();

        fs::write(root.join("control.pem"), cert.to_pem().unwrap()).unwrap();

        fs::write(
            root.join("control.key"),
            key.private_key_to_pem_pkcs8().unwrap(),
        )
        .unwrap();
    }

    pub fn bundle(&self, host: &str, version: u64) -> InstallCertificateMaterialRequest {
        let (cert, key) = if version <= 2 {
            match std::env::var_os("APOLLO_TEST_ISSUED_CERT_DIR") {
                Some(path) => {
                    let root = std::path::PathBuf::from(path).join(version.to_string());

                    (
                        X509::stack_from_pem(&fs::read(root.join("certificate.pem")).unwrap())
                            .unwrap()
                            .remove(0),
                        PKey::private_key_from_pem(
                            &fs::read(root.join("private-key.pem")).unwrap(),
                        )
                        .unwrap(),
                    )
                }
                None => self.leaf(host, version as u32 + 100),
            }
        } else {
            self.leaf(host, version as u32 + 100)
        };

        let mut chain = cert.to_pem().unwrap();

        if version <= 2 && std::env::var_os("APOLLO_TEST_ISSUED_CERT_DIR").is_some() {
            let root =
                std::path::PathBuf::from(std::env::var_os("APOLLO_TEST_ISSUED_CERT_DIR").unwrap())
                    .join(version.to_string());

            chain = fs::read(root.join("certificate.pem")).unwrap();
        } else {
            chain.extend(self.ca.to_pem().unwrap());
        }

        let mut der = Vec::new();

        for certificate in X509::stack_from_pem(&chain).unwrap() {
            der.extend(certificate.to_der().unwrap());
        }

        InstallCertificateMaterialRequest {
            organization_id: "org".into(),
            project_id: "project".into(),
            certificate_id: "cert".into(),
            certificate_version: version,
            certificate_chain_pem: chain,
            private_key_pem: key.private_key_to_pem_pkcs8().unwrap(),
            public_key_sha256: Sha256::digest(
                cert.public_key().unwrap().public_key_to_der().unwrap(),
            )
            .to_vec(),
            certificate_chain_sha256: Sha256::digest(der).to_vec(),
        }
    }
}

pub fn apply(
    bundle: &InstallCertificateMaterialRequest,
    backend_ip: std::net::IpAddr,
    backend_port: u16,
    generation: u64,
) -> ApplyConfigurationRequest {
    let identity = ProductIdentity {
        organization_id: "org".into(),
        project_id: "project".into(),
        service_id: "service".into(),
        deployment_id: "deployment".into(),
        release_id: "release".into(),
        route_id: "route".into(),
        traffic_target_id: "target".into(),
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let mut config = EdgeConfiguration {
        identity: Some(identity.clone()),
        controller_epoch: 1,
        generation,
        issued_at_unix_ms: now - 1000,
        valid_until_unix_ms: now + 600_000,
        max_header_bytes: 65536,
        max_body_bytes: 1048576,
        max_connections: 1024,
        max_concurrency: 1024,
        drain_timeout_seconds: 5,
        retry_max_attempts: 1,
        semantic_hash: vec![1; 32],
        routes: vec![EdgeRoute {
            identity: Some(identity.clone()),
            hostname: "api.example.com".into(),
            path_match: "/".into(),
            protocols: vec![EdgeProtocol::Http1 as i32, EdgeProtocol::Http2 as i32],
            route_generation: generation,
            tls: Some(EdgeTlsBinding {
                certificate_id: "cert".into(),
                certificate_version: bundle.certificate_version,
                hostname: "api.example.com".into(),
                material_reference: format!("org/project/cert/{}", bundle.certificate_version),
                public_certificate_hash: bundle.public_key_sha256.clone(),
                certificate_chain_hash: bundle.certificate_chain_sha256.clone(),
            }),
            backends: vec![EdgeBackend {
                endpoint: Some(WorkloadEndpoint {
                    workload_id: "workload".into(),
                    workload_generation: 1,
                    node_id: "node".into(),
                    region_id: "region".into(),
                    cell_id: "cell".into(),
                    address: backend_ip.to_string(),
                    port: u32::from(backend_port),
                    protocol: EdgeProtocol::Http1 as i32,
                    network_scope: NetworkScope::CellPrivate as i32,
                    observed_at_unix_ms: now,
                    ready: true,
                    healthy: true,
                }),
                health_requirement: BackendHealthRequirement::ReadyAndHealthy as i32,
                weight: 1,
                draining: false,
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    config.configuration_hash = Sha256::digest(config.encode_to_vec()).to_vec();

    ApplyConfigurationRequest {
        identity: Some(identity),
        operation: Some(OperationIdentity {
            operation_id: format!("activate-{generation}"),
            effect_id: format!("effect-{generation}"),
            controller_epoch: 1,
            generation,
            configuration_hash: config.configuration_hash.clone(),
        }),
        configuration: Some(config),
    }
}
