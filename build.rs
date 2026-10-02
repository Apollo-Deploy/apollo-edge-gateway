fn main() -> Result<(), Box<dyn std::error::Error>> {
    const SCHEMA: &str = "proto/apollo/edge/edge_control.proto";
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={SCHEMA}");
    println!("cargo:rerun-if-env-changed=PROTOC");
    println!("cargo:rerun-if-env-changed=PROTOC_INCLUDE");
    let mut config = prost_build::Config::new();
    config.type_attribute(
        ".apollo.edge.ControlRequest.payload",
        "#[allow(clippy::large_enum_variant)]",
    );
    config.compile_protos(&[SCHEMA], &["proto"])?;
    Ok(())
}
