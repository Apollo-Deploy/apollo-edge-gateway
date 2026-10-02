//! Process startup: recover state, start authenticated control, then serve traffic.

mod config;

use std::path::Path;
use std::sync::Arc;

use pingora::prelude::Server;
use pingora::proxy::http_proxy_service;

use crate::GatewayState;
use crate::material::canonical_root;
use crate::proxy::{ApolloGateway, tls_settings};
use crate::state::StateStore;
use crate::transport::ControlServer;

use self::config::{
    control_config_from_environment, required_environment, state_path_from_environment,
};

/// Starts the gateway using its `APOLLO_EDGE_*` environment configuration.
///
/// State and certificate material are recovered and the authenticated control
/// listener is initialized before Pingora starts accepting public traffic.
/// On successful startup, this function runs the server indefinitely.
///
/// # Errors
///
/// Returns an error when required configuration is missing, persisted state or
/// certificate material is invalid, or either listener cannot be initialized.
pub fn run() -> anyhow::Result<()> {
    let state_path = state_path_from_environment()?;
    let material_directory = canonical_root(Path::new(&required_environment(
        "APOLLO_EDGE_CERTIFICATE_MATERIAL_DIR",
    )?))?;
    let state = Arc::new(
        GatewayState::from_store(StateStore::new(state_path))?
            .with_certificate_material_directory(material_directory.clone())?,
    );
    let control_config = control_config_from_environment()?;
    let _control_server = ControlServer::new(control_config, Arc::clone(&state)).spawn()?;
    let mut server = Server::new(None)?;
    let configuration = Arc::get_mut(&mut server.configuration)
        .ok_or_else(|| anyhow::anyhow!("Pingora configuration is already shared"))?;
    configuration.max_retries = 2;
    configuration.grace_period_seconds = Some(0);
    configuration.graceful_shutdown_timeout_seconds = Some(5);
    server.bootstrap();
    let mut service = http_proxy_service(
        &server.configuration,
        ApolloGateway::new(Arc::clone(&state)),
    );
    let listen_address = required_environment("APOLLO_EDGE_LISTEN")?;
    let tls = tls_settings(Arc::clone(&state), material_directory)?;
    service.add_tls_with_settings(&listen_address, None, tls);
    server.add_service(service);
    server.run_forever();
}
