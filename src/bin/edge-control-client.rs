use std::env;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use apollo_edge_gateway::control::{
    self, ApplyConfigurationRequest, BackendHealthRequirement, ControlRequest, EdgeBackend,
    EdgeConfiguration, EdgeProtocol, EdgeRoute, EdgeTlsBinding, NetworkScope, OperationIdentity,
    ProductIdentity, WorkloadEndpoint, control_request,
};
use openssl::ssl::{SslConnector, SslFiletype, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

const FRAME_LIMIT: usize = 4 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let address = args.next().context("missing gateway address")?;
    let ca = args.next().context("missing CA path")?;
    let certificate = args.next().context("missing client certificate path")?;
    let private_key = args.next().context("missing client key path")?;
    let backend_port: u32 = args
        .next()
        .context("missing backend port")?
        .parse()
        .context("invalid backend port")?;
    let workload_generation: u64 = args
        .next()
        .context("missing workload generation")?
        .parse()
        .context("invalid workload generation")?;
    let configuration_generation: u64 = args
        .next()
        .context("missing configuration generation")?
        .parse()
        .context("invalid configuration generation")?;
    let edge_certificate = args.next().context("missing edge certificate path")?;
    if args.next().is_some()
        || !(1024..=u16::MAX as u32).contains(&backend_port)
        || workload_generation == 0
        || configuration_generation == 0
    {
        anyhow::bail!(
            "usage: edge-control-client <address> <ca> <certificate> <private-key> <backend-port> <workload-generation> <configuration-generation> <edge-certificate>"
        );
    }

    let certificates = X509::stack_from_pem(&std::fs::read(&edge_certificate)?)
        .context("invalid edge certificate chain")?;
    let leaf = certificates
        .first()
        .context("edge certificate chain is empty")?;
    let public_certificate_hash = Sha256::digest(leaf.public_key()?.public_key_to_der()?).to_vec();
    let mut chain_der = Vec::new();
    for certificate in &certificates {
        chain_der.extend_from_slice(&certificate.to_der()?);
    }
    let certificate_chain_hash = Sha256::digest(chain_der).to_vec();

    let now = env::var("APOLLO_EDGE_TEST_NOW_MS")
        .ok()
        .map(|value| {
            value
                .parse::<i64>()
                .context("APOLLO_EDGE_TEST_NOW_MS must be a signed millisecond timestamp")
        })
        .transpose()?
        .unwrap_or(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("clock before epoch")?
                .as_millis() as i64,
        );
    let identity = ProductIdentity {
        organization_id: "edge-test-organization".into(),
        project_id: "edge-test-project".into(),
        service_id: "edge-test-service".into(),
        deployment_id: "edge-test-deployment".into(),
        release_id: "edge-test-release".into(),
        route_id: "edge-test-route".into(),
        traffic_target_id: "edge-test-target".into(),
    };
    let endpoint = WorkloadEndpoint {
        workload_id: "edge-test-workload".into(),
        workload_generation,
        node_id: "edge-test-node".into(),
        region_id: "edge-test-region".into(),
        cell_id: "edge-test-cell".into(),
        address: "10.88.0.1".into(),
        port: backend_port,
        protocol: EdgeProtocol::Http1 as i32,
        network_scope: NetworkScope::CellPrivate as i32,
        observed_at_unix_ms: now,
        ready: true,
        healthy: true,
    };
    let route = EdgeRoute {
        identity: Some(identity.clone()),
        hostname: "edge.test".into(),
        path_match: "/".into(),
        methods: vec!["GET".into(), "HEAD".into()],
        protocols: vec![EdgeProtocol::Http1 as i32],
        backends: vec![EdgeBackend {
            endpoint: Some(endpoint),
            health_requirement: BackendHealthRequirement::ReadyAndHealthy as i32,
            weight: 1,
            draining: false,
        }],
        tls: Some(EdgeTlsBinding {
            certificate_id: "edge-test-certificate".into(),
            certificate_version: 1,
            hostname: "edge.test".into(),
            material_reference: "edge-test-certificate-material".into(),
            public_certificate_hash,
            certificate_chain_hash,
        }),
        route_generation: configuration_generation,
    };
    let mut configuration = EdgeConfiguration {
        identity: Some(identity.clone()),
        controller_epoch: 1,
        generation: configuration_generation,
        issued_at_unix_ms: now,
        valid_until_unix_ms: now + 10 * 60 * 1_000,
        routes: vec![route],
        max_header_bytes: 64 * 1024,
        max_body_bytes: 8 * 1024 * 1024,
        max_connections: 256,
        max_concurrency: 256,
        drain_timeout_seconds: 30,
        retry_max_attempts: 1,
        retry_methods: vec!["GET".into(), "HEAD".into()],
        semantic_hash: Sha256::digest(b"edge-test-configuration").to_vec(),
        ..Default::default()
    };
    configuration.configuration_hash = configuration_hash(&configuration);
    let operation = OperationIdentity {
        operation_id: "edge-test-apply".into(),
        effect_id: "edge-test-apply-effect".into(),
        controller_epoch: configuration.controller_epoch,
        generation: configuration.generation,
        configuration_hash: configuration.configuration_hash.clone(),
    };
    let request = ControlRequest {
        payload: Some(control_request::Payload::ApplyConfiguration(
            ApplyConfigurationRequest {
                operation: Some(operation),
                identity: Some(identity),
                configuration: Some(configuration),
            },
        )),
    };

    let mut builder = SslConnector::builder(SslMethod::tls_client())?;
    builder.set_verify(SslVerifyMode::PEER);
    builder.set_ca_file(ca)?;
    builder.set_certificate_chain_file(certificate)?;
    builder.set_private_key_file(private_key, SslFiletype::PEM)?;
    let ssl = builder.build().configure()?.into_ssl("edge-control")?;
    let socket = TcpStream::connect(&address).await?;
    let mut stream = SslStream::new(ssl, socket)?;
    Pin::new(&mut stream).connect().await?;

    let encoded = request.encode_to_vec();
    if encoded.is_empty() || encoded.len() > FRAME_LIMIT {
        anyhow::bail!("control request exceeds the configured bound");
    }
    stream
        .write_all(&(encoded.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(&encoded).await?;
    stream.flush().await?;

    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > FRAME_LIMIT {
        anyhow::bail!("control response exceeds the configured bound");
    }
    let mut response_bytes = vec![0u8; length];
    stream.read_exact(&mut response_bytes).await?;
    let response = control::ControlResponse::decode(response_bytes.as_slice())?;
    match response.payload {
        Some(control::control_response::Payload::Command(command)) => {
            println!(
                "result={:?} generation={} hash={} error_code={} retryable={}",
                command.result(),
                command.generation,
                hex(&command.configuration_hash),
                command.error_code,
                command.retryable
            );
        }
        other => println!("unexpected control response: {}", response_kind(other)),
    }
    Ok(())
}

fn configuration_hash(configuration: &EdgeConfiguration) -> Vec<u8> {
    let mut unsigned = configuration.clone();
    unsigned.configuration_hash.clear();
    Sha256::digest(unsigned.encode_to_vec()).to_vec()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn response_kind(response: Option<control::control_response::Payload>) -> &'static str {
    match response {
        Some(control::control_response::Payload::Configuration(_)) => "configuration",
        Some(control::control_response::Payload::Capabilities(_)) => "capabilities",
        Some(control::control_response::Payload::Status(_)) => "status",
        Some(control::control_response::Payload::Command(_)) => "command",
        None => "empty",
    }
}
