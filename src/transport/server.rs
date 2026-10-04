use std::pin::Pin;
use std::sync::{Arc, mpsc::sync_channel};

use openssl::ssl::{Ssl, SslAcceptor};
use prost::Message;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::{Duration, timeout};
use tokio_openssl::SslStream;
use zeroize::Zeroizing;

use crate::control::{ControlRequest, GatewayState};

use super::dispatch::dispatch;
use super::framing::{read_frame, write_frame};
use super::tls::{authorize_peer, build_acceptor};

#[derive(Clone, Debug)]
pub struct ControlConfig {
    pub listen_address: String,
    pub gateway_id: String,
    pub ca_certificate: String,
    pub certificate: String,
    pub private_key: String,
    pub certificate_material_configured: bool,
}

pub struct ControlServer {
    config: ControlConfig,
    state: Arc<GatewayState>,
}

impl ControlServer {
    pub fn new(config: ControlConfig, state: Arc<GatewayState>) -> Self {
        Self { config, state }
    }

    pub fn spawn(self) -> anyhow::Result<std::thread::JoinHandle<()>> {
        // Bind and validate TLS before the public listener can accept traffic.
        let listener = std::net::TcpListener::bind(&self.config.listen_address)?;

        listener.set_nonblocking(true)?;

        let acceptor = Arc::new(build_acceptor(&self.config)?);

        let (ready, initialized) = sync_channel(1);

        let name = format!("apollo-edge-control-{}", self.config.gateway_id);

        let thread = std::thread::Builder::new().name(name).spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = ready.send(Err(error));

                    return;
                }
            };

            let listener = match runtime.block_on(async { TcpListener::from_std(listener) }) {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = ready.send(Err(error));

                    return;
                }
            };

            if ready.send(Ok(())).is_err() {
                return;
            }

            if let Err(error) = runtime.block_on(self.run(listener, acceptor)) {
                eprintln!("edge control server stopped: {error}");
            }
            // Management failure must not terminate existing public traffic.
            // Local health, lease expiry and cached certificates remain authoritative.
        })?;

        initialized.recv()??;

        Ok(thread)
    }

    async fn run(self, listener: TcpListener, acceptor: Arc<SslAcceptor>) -> anyhow::Result<()> {
        let capacity = Arc::new(Semaphore::new(64));

        let mut connection_id = 0u64;

        loop {
            let (socket, _) = match listener.accept().await {
                Ok(peer) => peer,
                Err(error) => {
                    eprintln!("control accept failed; continuing local serving: {error}");

                    return Err(error.into());
                }
            };

            let Ok(permit) = Arc::clone(&capacity).try_acquire_owned() else {
                drop(socket);

                continue;
            };

            connection_id = connection_id.wrapping_add(1).max(1);

            let acceptor = Arc::clone(&acceptor);

            let state = Arc::clone(&self.state);

            let gateway_id = self.config.gateway_id.clone();

            let tls_termination = self.config.certificate_material_configured;

            let session_id = format!("{gateway_id}-{connection_id}");

            tokio::spawn(async move {
                let _permit = permit;

                if let Err(error) = serve_connection(
                    socket,
                    acceptor,
                    state,
                    gateway_id,
                    session_id,
                    tls_termination,
                )
                .await
                {
                    eprintln!("edge control connection failed: {error}");
                }
            });
        }
    }
}

async fn serve_connection(
    socket: TcpStream,
    acceptor: Arc<SslAcceptor>,
    state: Arc<GatewayState>,
    gateway_id: String,
    session_id: String,
    tls_termination: bool,
) -> anyhow::Result<()> {
    let ssl = Ssl::new(acceptor.context())?;

    let mut stream = SslStream::new(ssl, socket)?;

    timeout(Duration::from_secs(5), Pin::new(&mut stream).accept()).await??;

    authorize_peer(stream.ssl().peer_certificate(), &gateway_id)?;

    loop {
        let frame = match read_frame(&mut stream).await? {
            Some(frame) => frame,
            None => return Ok(()),
        };

        let frame = Zeroizing::new(frame);

        let request = ControlRequest::decode(frame.as_slice())?;

        let response = dispatch(request, &state, &gateway_id, &session_id, tls_termination);

        timeout(
            Duration::from_secs(5),
            write_frame(&mut stream, &response.encode_to_vec()),
        )
        .await??;
    }
}
