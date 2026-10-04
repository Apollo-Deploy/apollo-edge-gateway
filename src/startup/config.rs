//! Environment configuration for the public and authenticated control listeners.
use crate::transport::ControlConfig;

pub(super) fn state_path_from_environment() -> anyhow::Result<String> {
    match std::env::var("APOLLO_EDGE_STATE_PATH") {
        Ok(path) if !path.is_empty() => Ok(path),
        _ => Err(anyhow::anyhow!("APOLLO_EDGE_STATE_PATH is required")),
    }
}

pub(super) fn control_config_from_environment() -> anyhow::Result<ControlConfig> {
    Ok(ControlConfig {
        listen_address: required_environment("APOLLO_EDGE_CONTROL_LISTEN")?,
        gateway_id: required_environment("APOLLO_EDGE_GATEWAY_ID")?,
        ca_certificate: required_environment("APOLLO_EDGE_CONTROL_CA")?,
        certificate: required_environment("APOLLO_EDGE_CONTROL_CERTIFICATE")?,
        private_key: required_environment("APOLLO_EDGE_CONTROL_PRIVATE_KEY")?,
        certificate_material_configured: true,
    })
}

pub(super) fn required_environment(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).map_err(|_| anyhow::anyhow!("{name} is required"))?;

    if value.is_empty() {
        return Err(anyhow::anyhow!("{name} must not be empty"));
    }

    Ok(value)
}
