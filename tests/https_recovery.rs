//! Live Pingora HTTPS proof using local certificates, backend and durable state.
mod support;

use apollo_edge_gateway::{GatewayState, control::*, state::StateStore};
use openssl::ssl::{SslConnector, SslMethod};
use prost::Message;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use support::{Pki, apply};

struct Process(Child);

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();

        let _ = self.0.wait();
    }
}

fn address() -> String {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

fn start(root: &Path, public: &str, control: &str) -> Process {
    let log = fs::File::create(root.join("gateway.log")).unwrap();

    Process(
        Command::new(env!("CARGO_BIN_EXE_apollo-edge-gateway"))
            .env("APOLLO_EDGE_STATE_PATH", root.join("gateway.state"))
            .env(
                "APOLLO_EDGE_CERTIFICATE_MATERIAL_DIR",
                root.join("material"),
            )
            .env("APOLLO_EDGE_LISTEN", public)
            .env("APOLLO_EDGE_CONTROL_LISTEN", control)
            .env("APOLLO_EDGE_GATEWAY_ID", "gateway-test")
            .env("APOLLO_EDGE_CONTROL_CA", root.join("ca.pem"))
            .env("APOLLO_EDGE_CONTROL_CERTIFICATE", root.join("control.pem"))
            .env("APOLLO_EDGE_CONTROL_PRIVATE_KEY", root.join("control.key"))
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    )
}

fn https(pki: &Pki, addr: &str) -> anyhow::Result<(String, String)> {
    let socket = TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(1))?;

    socket.set_read_timeout(Some(Duration::from_secs(2)))?;

    socket.set_write_timeout(Some(Duration::from_secs(2)))?;

    let mut builder = SslConnector::builder(SslMethod::tls_client())?;

    builder.cert_store_mut().add_cert(pki.ca.clone())?;

    if let Some(path) = std::env::var_os("APOLLO_TEST_ISSUED_CERT_DIR") {
        for certificate in openssl::x509::X509::stack_from_pem(&fs::read(
            std::path::PathBuf::from(path).join("root.pem"),
        )?)? {
            builder.cert_store_mut().add_cert(certificate)?;
        }
    }

    let mut stream = builder.build().connect("api.example.com", socket)?;

    let serial = stream
        .ssl()
        .peer_certificate()
        .unwrap()
        .serial_number()
        .to_bn()?
        .to_dec_str()?
        .to_string();

    stream.write_all(b"GET / HTTP/1.1\r\nHost: api.example.com\r\nConnection: close\r\n\r\n")?;

    let mut response = String::new();

    // Some servers close TLS without close_notify after a Connection: close response.
    let _ = stream.read_to_string(&mut response);

    Ok((response, serial))
}

fn ready(pki: &Pki, addr: &str, serial: &str, root: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);

    loop {
        let result = https(pki, addr);

        if let Ok((response, actual)) = &result {
            if response.contains("200 OK") && response.ends_with("alive") && actual == serial {
                return;
            }
        }

        assert!(
            Instant::now() < deadline,
            "gateway did not serve HTTPS with serial {serial}: {result:?}; log={}",
            fs::read_to_string(root.join("gateway.log")).unwrap_or_default()
        );

        std::thread::sleep(Duration::from_millis(100));
    }
}

fn deliver(
    pki: &Pki,
    root: &Path,
    addr: &str,
    payload: control_request::Payload,
) -> ControlResponse {
    let mut builder = SslConnector::builder(SslMethod::tls_client()).unwrap();

    builder.cert_store_mut().add_cert(pki.ca.clone()).unwrap();

    // The management client identity must be gateway-test and signed by the CA.
    let (cert, key) = pki.leaf("gateway-test", 20);

    builder.set_certificate(&cert).unwrap();

    builder.set_private_key(&key).unwrap();

    let socket = TcpStream::connect(addr).unwrap();

    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut stream = builder.build().connect("gateway-test", socket).unwrap();

    let request = ControlRequest {
        payload: Some(payload),
    }
    .encode_to_vec();

    stream
        .write_all(&(request.len() as u32).to_be_bytes())
        .unwrap();

    stream.write_all(&request).unwrap();

    let mut header = [0; 4];

    stream.read_exact(&mut header).unwrap();

    let length = u32::from_be_bytes(header) as usize;

    assert!(length <= 4 * 1024 * 1024);

    let mut response = vec![0; length];

    stream.read_exact(&mut response).unwrap();

    let _ = root;

    ControlResponse::decode(response.as_slice()).unwrap()
}

#[test]
fn unavailable_management_restart_atomic_renewal_and_failed_replacement() {
    let root = tempfile::tempdir().unwrap();

    fs::create_dir(root.path().join("material")).unwrap();

    let pki = Pki::new();

    pki.write_control(root.path());

    // Serving policy deliberately rejects loopback backends. Use the host's
    // private interface without adding a test-only admission bypass.
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();

    probe.connect("192.0.2.1:9").unwrap();

    let backend_ip = probe.local_addr().unwrap().ip();

    let backend = TcpListener::bind((backend_ip, 0)).unwrap();

    let port = backend.local_addr().unwrap().port();

    // One fixed backend thread; probes and HTTP requests share the listener.
    let backend_thread = std::thread::spawn(move || {
        for mut socket in backend.incoming().flatten() {
            let _ = socket.set_read_timeout(Some(Duration::from_secs(1)));

            let mut request = [0; 2048];

            if socket.read(&mut request).unwrap_or(0) > 0 {
                let _ = socket.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nalive",
                );
            }
        }
    });

    let bundle1 = pki.bundle("api.example.com", 1);

    let state = Arc::new(
        GatewayState::from_store(StateStore::new(root.path().join("gateway.state")))
            .unwrap()
            .with_certificate_material_directory(root.path().join("material"))
            .unwrap(),
    );

    assert!(matches!(
        state.install_certificate_material(&bundle1),
        CommandOutcome::Accepted
    ));

    assert!(matches!(
        state.apply(apply(&bundle1, backend_ip, port, 1)),
        CommandOutcome::Accepted
    ));

    let serial1 = openssl::x509::X509::stack_from_pem(&bundle1.certificate_chain_pem).unwrap()[0]
        .serial_number()
        .to_bn()
        .unwrap()
        .to_dec_str()
        .unwrap()
        .to_string();

    let public = address();

    let control = address();

    let gateway = start(root.path(), &public, &control);

    // Neither certd, dnsd, nor an external controller exists: fresh HTTPS handshakes still serve.
    ready(&pki, &public, &serial1, root.path());

    let bundle2 = pki.bundle("api.example.com", 2);

    let serial2 = openssl::x509::X509::stack_from_pem(&bundle2.certificate_chain_pem).unwrap()[0]
        .serial_number()
        .to_bn()
        .unwrap()
        .to_dec_str()
        .unwrap()
        .to_string();

    deliver(
        &pki,
        root.path(),
        &control,
        control_request::Payload::InstallCertificateMaterial(bundle2.clone()),
    );

    ready(&pki, &public, &serial1, root.path()); // install alone cannot mutate active routing authority
    let mut renewed = apply(&bundle2, backend_ip, port, 2);

    let mut alternate = apply(&bundle1, backend_ip, port, 2)
        .configuration
        .unwrap()
        .routes
        .remove(0);

    alternate.path_match = "/alternate".into();

    renewed
        .configuration
        .as_mut()
        .unwrap()
        .routes
        .push(alternate);

    let configuration = renewed.configuration.as_mut().unwrap();

    configuration.configuration_hash.clear();

    configuration.configuration_hash = Sha256::digest(configuration.encode_to_vec()).to_vec();

    renewed.operation.as_mut().unwrap().configuration_hash =
        configuration.configuration_hash.clone();

    deliver(
        &pki,
        root.path(),
        &control,
        control_request::Payload::ApplyConfiguration(renewed),
    );

    ready(&pki, &public, &serial2, root.path());

    let mut broken = pki.bundle("api.example.com", 3);

    broken.private_key_pem = b"invalid key".to_vec();

    deliver(
        &pki,
        root.path(),
        &control,
        control_request::Payload::InstallCertificateMaterial(broken.clone()),
    );

    deliver(
        &pki,
        root.path(),
        &control,
        control_request::Payload::ApplyConfiguration(apply(&broken, backend_ip, port, 3)),
    );

    ready(&pki, &public, &serial2, root.path());

    // Wrong SAN can install as material, but cannot activate for this hostname.
    let wrong_host = pki.bundle("other.example.com", 4);

    deliver(
        &pki,
        root.path(),
        &control,
        control_request::Payload::InstallCertificateMaterial(wrong_host.clone()),
    );

    deliver(
        &pki,
        root.path(),
        &control,
        control_request::Payload::ApplyConfiguration(apply(&wrong_host, backend_ip, port, 4)),
    );

    ready(&pki, &public, &serial2, root.path());

    // Rollback keeps the authority fence monotonic while reusing the old valid material.
    deliver(
        &pki,
        root.path(),
        &control,
        control_request::Payload::ApplyConfiguration(apply(&bundle1, backend_ip, port, 5)),
    );

    ready(&pki, &public, &serial1, root.path());

    deliver(
        &pki,
        root.path(),
        &control,
        control_request::Payload::ApplyConfiguration(apply(&bundle2, backend_ip, port, 6)),
    );

    ready(&pki, &public, &serial2, root.path());

    drop(gateway);

    // The management listener is unavailable during restart, but local health
    // and serving must recover independently from the durable snapshot.
    let blocked_control = TcpListener::bind(&control).unwrap();

    let recovered = start(root.path(), &public, &control);

    ready(&pki, &public, &serial2, root.path());

    // Removing the local material after admission proves HTTPS does no disk read.
    fs::rename(
        root.path().join("material"),
        root.path().join("offline-material"),
    )
    .unwrap();

    ready(&pki, &public, &serial2, root.path());

    drop(recovered);

    drop(blocked_control);

    // Detached fixed fixture worker terminates with the test process.
    drop(backend_thread);
}
