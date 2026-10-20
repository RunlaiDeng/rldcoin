//! Public signed-operation API and bounded pinned-TLS neighbor exchanges.
use crate::{
    custody::Vault,
    runtime::{Committed, Node},
    store::{private_create, read_bounded},
    transport::{self, Acknowledgment, Challenge, Challenges, Exchange, Peer, Spool},
};
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, Query, State as AxumState},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rld_protocol::{
    codec::{Blob, Id, decode, encode},
    model::*,
    proof::{self, NativeInput},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::Cursor,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub tls_certificate: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub peers: Vec<Peer>,
    pub spool: PathBuf,
    pub spool_bytes: u64,
    pub proof_executable: Option<PathBuf>,
    pub proof_work: PathBuf,
}
struct Shared {
    node: Node,
    transport: Vault,
    spool: Spool,
    challenges: Challenges,
    peers: Vec<Peer>,
    processed: BTreeSet<Id>,
    route_hints: Vec<Id>,
    advertisements: Vec<transport::Advertisement>,
    last_contact_error: Option<String>,
}
type SharedState = Arc<Mutex<Shared>>;
#[derive(Debug)]
struct ApiError(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        Self(e.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error":self.0.to_string(),"settled":false})),
        )
            .into_response()
    }
}
type ApiResult<T> = std::result::Result<T, ApiError>;
fn wire<T: minicbor::Encode<()>>(v: &T) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/cbor")],
        encode(v),
    )
        .into_response()
}
fn origin(headers: &HeaderMap) -> Result<()> {
    ensure!(
        !headers.contains_key("origin"),
        "browser-origin requests are not a wallet signing interface"
    );
    Ok(())
}
async fn job<T: Send + 'static>(
    shared: SharedState,
    f: impl FnOnce(&mut Shared) -> Result<T> + Send + 'static,
) -> ApiResult<T> {
    static PUBLIC_JOBS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(2)));
    let permit = PUBLIC_JOBS.clone().try_acquire_owned().map_err(|_| {
        anyhow::anyhow!("public request capacity exhausted; retry without changing monetary intent")
    })?;
    Ok(tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut guard = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("node state unavailable"))?;
        f(&mut guard)
    })
    .await??)
}

async fn status(AxumState(s): AxumState<SharedState>) -> ApiResult<Response> {
    job(s,|s|Ok(axum::Json(serde_json::json!({"protocol":rld_protocol::PROTOCOL,"currency":s.node.core.state.currency,"domain":s.node.core.state.domain,"height":s.node.core.state.sequence,"checkpoint":s.node.core.head,"journal_head":s.node.journal_tip(),"queued":s.node.core.pending.len(),"latest_execution_receipt":s.node.core.proofs.last().map(|p|p.header.sequence),"unresolved_controllers":s.node.core.state.controllers.iter().filter(|c|s.node.core.terminal_statement(c.id).is_none()).count(),"last_error":s.node.last_error,"last_contact_error":s.last_contact_error,"runtime_security_qualified":false,"physical_stellar_route_qualified":false})).into_response())).await
}
async fn routes(AxumState(s): AxumState<SharedState>) -> ApiResult<Response> {
    job(s, |s| Ok(wire(&s.advertisements))).await
}
async fn initial(AxumState(s): AxumState<SharedState>) -> ApiResult<Response> {
    job(s, |s| Ok(wire(&s.node.core.initial))).await
}
#[derive(Deserialize)]
struct Page {
    after: Option<u64>,
    limit: Option<usize>,
}
async fn blocks(
    AxumState(s): AxumState<SharedState>,
    Query(page): Query<Page>,
) -> ApiResult<Response> {
    job(s, move |s| {
        let after = page.after.unwrap_or(0);
        let limit = page.limit.unwrap_or(16).min(128);
        let mut out: Vec<Committed> = vec![];
        let mut bytes = 1024;
        for block in s
            .node
            .core
            .history
            .iter()
            .filter(|c| c.header.sequence > after)
            .take(limit)
        {
            let n = encode(block).len();
            if bytes + n > rld_protocol::MAX_CAPSULE {
                break;
            }
            bytes += n;
            out.push(block.clone());
        }
        Ok(wire(&out))
    })
    .await
}
async fn snapshot(AxumState(s): AxumState<SharedState>) -> ApiResult<Response> {
    job(s, |s| {
        ensure!(
            encode(&s.node.core.state).len() <= rld_protocol::MAX_CAPSULE,
            "current state requires paged access; use local full node"
        );
        Ok(wire(&s.node.core.state))
    })
    .await
}
async fn certified(AxumState(s): AxumState<SharedState>) -> ApiResult<Response> {
    job(s, |s| {
        let p = s
            .node
            .core
            .proofs
            .iter()
            .find(|p| p.header.sequence == s.node.core.state.sequence)
            .context(
                "current execution receipt pending; no independently verified balance response",
            )?;
        Ok(wire(p))
    })
    .await
}
async fn work(AxumState(s): AxumState<SharedState>) -> ApiResult<Response> {
    job(s, |s| {
        let tasks: Vec<_> = s
            .node
            .core
            .state
            .segments
            .iter()
            .take(256)
            .map(|segment| {
                let grant = s
                    .node
                    .core
                    .state
                    .grants
                    .iter()
                    .find(|g| g.id == segment.grant)
                    .expect("validated grant");
                (grant.clone(), segment.clone())
            })
            .collect();
        Ok(wire(&(
            s.node.core.initial.currency.clone(),
            s.node.core.state.configuration.clone(),
            s.node
                .core
                .state
                .covers
                .iter()
                .filter(|cover| {
                    tasks
                        .iter()
                        .any(|(g, _)| g.cover == cover.id(s.node.core.state.currency))
                })
                .cloned()
                .collect::<Vec<_>>(),
            tasks,
        )))
    })
    .await
}
async fn submit(
    AxumState(s): AxumState<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    origin(&headers)?;
    let op: Operation = decode(&body, rld_protocol::MAX_CAPSULE)?;
    job(s, move |s| {
        let id = s.node.submit(op)?;
        Ok(
            axum::Json(serde_json::json!({"operation":id,"queued":true,"settled":false}))
                .into_response(),
        )
    })
    .await
}
async fn candidate(
    AxumState(s): AxumState<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    origin(&headers)?;
    let payload: rld_protocol::consensus::Payload = decode(&body, rld_protocol::MAX_CAPSULE)?;
    job(s, move |s| {
        s.node.queue_candidate(payload)?;
        Ok(axum::Json(serde_json::json!({"queued":true,"settled":false})).into_response())
    })
    .await
}
async fn proof_upload(
    AxumState(s): AxumState<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    origin(&headers)?;
    let p: Certified = decode(&body, rld_protocol::MAX_CAPSULE)?;
    job(s, move |s| {
        s.node.certificate(p)?;
        Ok(StatusCode::NO_CONTENT.into_response())
    })
    .await
}
async fn hello(AxumState(s): AxumState<SharedState>) -> ApiResult<Response> {
    job(s, |s| {
        let c = s.challenges.issue(
            s.node.core.state.currency,
            s.node.core.state.domain,
            &s.transport,
        )?;
        Ok(wire(&c))
    })
    .await
}
async fn exchange(
    AxumState(s): AxumState<SharedState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    origin(&headers)?;
    let request: Exchange = decode(&body, rld_protocol::MAX_CAPSULE)?;
    job(s, move |s| {
        let peer = s
            .peers
            .iter()
            .find(|p| p.identity == request.sender)
            .context("contact identity is not a configured neighbor")?
            .clone();
        transport::verify_exchange(s.node.core.state.currency, &request, &peer)?;
        s.challenges.consume(request.challenge)?;
        let mut retained = Vec::new();
        for f in &request.items {
            if let Some(id) = s.spool.retain_fragment(f)? {
                retained.push(id)
            }
        }
        // Routing hints are observations only. They never modify configured endpoints,
        // certificate pins, currency descriptors or validator authority.
        s.advertisements
            .retain(|a| a.identity != request.advertisement.identity);
        s.advertisements.push(request.advertisement.clone());
        for hint in request
            .advertisement
            .hints
            .iter()
            .chain(&request.advertisement.domains)
        {
            if s.route_hints.len() < 512 && !s.route_hints.contains(hint) {
                s.route_hints.push(*hint);
            }
        }
        let ack =
            transport::acknowledge(s.node.core.state.currency, &s.transport, &request, retained)?;
        Ok(wire(&ack))
    })
    .await
}
async fn cancel_draft(
    AxumState(s): AxumState<SharedState>,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Response> {
    let id = Id::parse(&id)?;
    job(s, move |s| Ok(wire(&s.node.core.cancel_draft(id)?))).await
}
async fn controller(
    AxumState(s): AxumState<SharedState>,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Response> {
    let id = Id::parse(&id)?;
    job(s, move |s| {
        let c = s
            .node
            .core
            .state
            .controllers
            .iter()
            .find(|c| c.id == id)
            .context("controller not found")?;
        Ok(wire(&(
            c.clone(),
            s.node
                .core
                .state
                .births
                .iter()
                .find(|b| b.controller == id)
                .cloned(),
            s.node
                .core
                .terminals
                .iter()
                .find(|r| match &r.payload {
                    rld_protocol::consensus::Payload::Export(r) => r.terminal.controller == id,
                    rld_protocol::consensus::Payload::Cancel(r) => r.controller == id,
                    _ => false,
                })
                .cloned(),
        )))
    })
    .await
}

#[derive(Debug)]
struct Pinned {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pin: Id,
}
impl rustls::client::danger::ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        name: &rustls::pki_types::ServerName<'_>,
        ocsp: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if Id::digest(end.as_ref()) != self.pin {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        self.inner
            .verify_server_cert(end, intermediates, name, ocsp, now)
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, sig)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        sig: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, sig)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
fn certificates(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let pem = read_bounded(path, 1024 * 1024)?;
    let certs =
        rustls_pemfile::certs(&mut Cursor::new(pem)).collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        !certs.is_empty() && certs.len() <= 8,
        "TLS certificate chain bounds"
    );
    Ok(certs)
}
pub fn peer_client(peer: &Peer) -> Result<reqwest::Client> {
    let endpoint = reqwest::Url::parse(&peer.endpoint)?;
    ensure!(
        endpoint.scheme() == "https"
            && endpoint.username().is_empty()
            && endpoint.password().is_none()
            && endpoint.query().is_none()
            && endpoint.fragment().is_none(),
        "literal configured HTTPS endpoint required"
    );
    let certs = certificates(Path::new(&peer.certificate_pem))?;
    ensure!(
        Id::digest(certs[0].as_ref()) == peer.certificate_sha256,
        "configured certificate bytes do not match pin"
    );
    let mut roots = rustls::RootCertStore::empty();
    for c in certs {
        roots.add(c)?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()?;
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            inner,
            pin: peer.certificate_sha256,
        }))
        .with_no_client_auth();
    tls.resumption = rustls::client::Resumption::disabled();
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(10))
        .build()?)
}
async fn bounded_response(mut response: reqwest::Response) -> Result<Vec<u8>> {
    ensure!(
        response.status().is_success(),
        "peer HTTP status {}",
        response.status()
    );
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= rld_protocol::MAX_CAPSULE as u64),
        "peer response size"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes
                .len()
                .checked_add(chunk.len())
                .is_some_and(|n| n <= rld_protocol::MAX_CAPSULE),
            "peer response bytes"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
async fn contact(
    shared: SharedState,
    peer: Peer,
    client: reqwest::Client,
    cursor: usize,
) -> Result<()> {
    let hello = bounded_response(
        client
            .get(format!("{}/v1/hello", peer.endpoint.trim_end_matches('/')))
            .send()
            .await?,
    )
    .await?;
    let challenge: Challenge = decode(&hello, rld_protocol::MAX_CAPSULE)?;
    ensure!(
        challenge.identity == peer.identity && challenge.domain == peer.domain,
        "neighbor challenge binding"
    );
    let request = {
        let mut s = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("node unavailable"))?;
        let items = s.spool.pending(peer.identity, cursor)?;

        let currency = s.node.core.state.currency;
        let domain = s.node.core.state.domain;
        let hints = if s.route_hints.is_empty() {
            vec![]
        } else {
            s.route_hints
                .iter()
                .cycle()
                .skip(cursor % s.route_hints.len())
                .take(32.min(s.route_hints.len()))
                .copied()
                .collect()
        };
        transport::make_exchange(currency, domain, &mut s.transport, &challenge, items, hints)?
    };
    let bytes = bounded_response(
        client
            .post(format!(
                "{}/v1/exchange",
                peer.endpoint.trim_end_matches('/')
            ))
            .header("content-type", "application/cbor")
            .body(encode(&request))
            .send()
            .await?,
    )
    .await?;
    let ack: Acknowledgment = decode(&bytes, rld_protocol::MAX_CAPSULE)?;
    let s = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("node unavailable"))?;
    s.spool.retain_ack(&peer, &request, &ack)?;
    Ok(())
}
async fn sync_blocks(shared: SharedState, peer: &Peer, client: &reqwest::Client) -> Result<()> {
    let (domain, after) = {
        let s = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("node unavailable"))?;
        (s.node.core.state.domain, s.node.core.state.sequence)
    };
    if peer.domain != domain {
        return Ok(());
    }
    let bytes = bounded_response(
        client
            .get(format!(
                "{}/v1/blocks?after={after}&limit=16",
                peer.endpoint.trim_end_matches('/')
            ))
            .send()
            .await?,
    )
    .await?;
    let blocks: Vec<Committed> = decode(&bytes, rld_protocol::MAX_CAPSULE)?;
    ensure!(blocks.len() <= 16, "sync block count");
    let mut s = shared
        .lock()
        .map_err(|_| anyhow::anyhow!("node unavailable"))?;
    for block in blocks {
        s.node.accept_block(block)?;
    }
    Ok(())
}
async fn peer_worker(shared: SharedState, peer: Peer, client: reqwest::Client) {
    let mut cursor = 0usize;
    loop {
        if let Err(error) = sync_blocks(shared.clone(), &peer, &client).await {
            if let Ok(mut s) = shared.lock() {
                s.last_contact_error = Some(error.to_string());
            }
        }
        if let Err(error) = contact(shared.clone(), peer.clone(), client.clone(), cursor).await {
            if let Ok(mut s) = shared.lock() {
                s.last_contact_error = Some(error.to_string());
            }
        }
        cursor = cursor.wrapping_add(1);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
async fn background(shared: SharedState) {
    loop {
        let s = shared.clone();
        let result = tokio::task::spawn_blocking(move || -> Result<()> {
            let mut s = s.lock().map_err(|_| anyhow::anyhow!("node unavailable"))?;
            if let Err(e) = s.node.tick() {
                s.node.last_error = Some(e.to_string());
            }
            for (id, dispatch) in s.node.core.outbox.clone() {
                s.spool.retain(&dispatch)?;
                s.node.acknowledge(id)?;
            }
            for (id, dispatch) in s.spool.packets()? {
                if dispatch.destination == s.node.core.state.domain && !s.processed.contains(&id) {
                    match s.node.ingest(dispatch) {
                        Ok(()) => {
                            s.processed.insert(id);
                        }
                        Err(error) => s.node.last_error = Some(error.to_string()),
                    }
                }
            }
            Ok(())
        })
        .await;
        if let Ok(Err(error)) = result {
            if let Ok(mut s) = shared.lock() {
                s.node.last_error = Some(error.to_string());
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

pub async fn serve(node: Node, transport: Vault, config: Config) -> Result<()> {
    ensure!(
        config.peers.len() <= 64
            && config
                .peers
                .iter()
                .map(|p| p.identity)
                .collect::<BTreeSet<_>>()
                .len()
                == config.peers.len(),
        "neighbor configuration bounds"
    );
    let mut clients = Vec::new();
    for peer in &config.peers {
        clients.push((peer.clone(), peer_client(peer)?));
    }
    let currency = node.core.state.currency;
    let spool = Spool::open(&config.spool, currency, config.spool_bytes, 4096)?;
    let shared = Arc::new(Mutex::new(Shared {
        node,
        transport,
        spool,
        challenges: Challenges::default(),
        peers: config.peers.clone(),
        processed: BTreeSet::new(),
        route_hints: vec![],
        advertisements: vec![],
        last_contact_error: None,
    }));
    let router = Router::new()
        .route("/v1/status", get(status))
        .route("/v1/initial", get(initial))
        .route("/v1/routes", get(routes))
        .route("/v1/blocks", get(blocks))
        .route("/v1/state", get(snapshot))
        .route("/v1/certified", get(certified))
        .route("/v1/work", get(work))
        .route("/v1/submit", post(submit))
        .route("/v1/candidate", post(candidate))
        .route("/v1/proof", post(proof_upload))
        .route("/v1/hello", get(hello))
        .route("/v1/exchange", post(exchange))
        .route("/v1/controller/{id}", get(controller))
        .route("/v1/cancel/{id}", get(cancel_draft))
        .layer(DefaultBodyLimit::max(rld_protocol::MAX_CAPSULE))
        .with_state(shared.clone());
    let background_task = tokio::spawn(background(shared.clone()));
    let peer_tasks: Vec<_> = clients
        .into_iter()
        .map(|(peer, client)| tokio::spawn(peer_worker(shared.clone(), peer, client)))
        .collect();
    let proof_task = config
        .proof_executable
        .clone()
        .map(|exe| tokio::spawn(proof_worker(shared.clone(), exe, config.proof_work.clone())));
    let result = if let (Some(certificate), Some(key)) = (&config.tls_certificate, &config.tls_key)
    {
        let certs = certificates(certificate)?;
        let key = rustls_pemfile::private_key(&mut Cursor::new(read_bounded(key, 1024 * 1024)?))?
            .context("TLS private key absent")?;
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        axum_server::bind_rustls(
            config.listen,
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls)),
        )
        .serve(router.into_make_service())
        .await
        .map_err(anyhow::Error::from)
    } else {
        ensure!(
            config.listen.ip().is_loopback()
                && config.tls_certificate.is_none()
                && config.tls_key.is_none(),
            "external listeners require TLS 1.3 certificate and key"
        );
        axum::serve(tokio::net::TcpListener::bind(config.listen).await?, router)
            .await
            .map_err(anyhow::Error::from)
    };
    background_task.abort();
    for task in peer_tasks {
        task.abort();
    }
    if let Some(task) = proof_task {
        task.abort();
    }
    result
}

async fn proof_worker(shared: SharedState, exe: PathBuf, work: PathBuf) {
    if let Err(e) = fs::create_dir_all(&work) {
        if let Ok(mut s) = shared.lock() {
            s.node.last_error = Some(e.to_string());
        }
        return;
    }
    let mut serial = 0u64;
    loop {
        let result = prove_next(shared.clone(), &exe, &work, serial).await;
        if let Err(error) = result {
            if let Ok(mut s) = shared.lock() {
                s.node.last_error = Some(format!("proof service: {error}"));
            }
        }
        serial = serial.wrapping_add(1);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}
async fn prove_next(shared: SharedState, exe: &Path, work: &Path, serial: u64) -> Result<()> {
    let target = {
        let s = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("node unavailable"))?;
        let pending = s
            .node
            .core
            .state
            .births
            .iter()
            .filter(|b| {
                s.node.core.terminal_statement(b.controller).is_none()
                    && !s
                        .node
                        .core
                        .state
                        .resolutions
                        .iter()
                        .any(|r| r.object == b.controller)
            })
            .filter(|b| {
                !s.node
                    .core
                    .proofs
                    .iter()
                    .any(|p| p.header.sequence == b.sequence)
            })
            .min_by_key(|b| b.sequence)
            .map(|b| b.sequence);
        if serial % 3 == 1 {
            None
        } else if serial % 3 == 0 && pending.is_some() {
            pending
        } else {
            (None)
                .or_else(|| {
                    let n = s.node.core.state.sequence;
                    if n > 0 && !s.node.core.proofs.iter().any(|p| p.header.sequence == n) {
                        Some(n)
                    } else {
                        None
                    }
                })
                .or(pending)
        }
    };
    if let Some(mut target) = target {
        let (input, header, qc, configuration) = {
            let s = shared
                .lock()
                .map_err(|_| anyhow::anyhow!("node unavailable"))?;
            let base = s
                .node
                .core
                .proofs
                .iter()
                .filter(|p| p.header.sequence < target)
                .map(|p| p.header.sequence)
                .max()
                .unwrap_or(0);
            target = target.min(
                base.checked_add(4096)
                    .context("proof position exhaustion")?,
            );
            let w = s.node.core.native_witness(target)?;
            let record = s
                .node
                .core
                .history
                .iter()
                .find(|b| b.header.sequence == target)
                .context("proof history")?;
            (
                NativeInput::Execution(w),
                record.header.clone(),
                record.qc.clone(),
                record.configuration.clone(),
            )
        };
        let receipt = run_prover(exe, work, serial, "native", &encode(&input)).await?;
        let p = Certified {
            header,
            receipt,
            qc,
            configuration,
        };
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("node unavailable"))?
            .node
            .certificate(p)?;
        return Ok(());
    }
    let candidate = {
        let s = shared
            .lock()
            .map_err(|_| anyhow::anyhow!("node unavailable"))?;
        s.node
            .core
            .state
            .controllers
            .iter()
            .find(|c| {
                s.node.core.terminal_statement(c.id).is_none()
                    && !s
                        .node
                        .core
                        .state
                        .resolutions
                        .iter()
                        .any(|r| r.object == c.id)
                    && s.node.core.creation(c.id).is_ok()
                    && !s.node.core.candidates.iter().any(|p| match p {
                        rld_protocol::consensus::Payload::Export(r) => {
                            r.creation.controller.id == c.id
                        }
                        rld_protocol::consensus::Payload::Cancel(r) => r.controller == c.id,
                        _ => false,
                    })
            })
            .map(|c| c.id)
    };
    if let Some(id) = candidate {
        let witness = {
            let s = shared
                .lock()
                .map_err(|_| anyhow::anyhow!("node unavailable"))?;
            let creation = s.node.core.creation(id)?;
            let c = &creation.controller;
            let born = s
                .node
                .core
                .history
                .iter()
                .find_map(|record| {
                    record
                        .batch
                        .operations
                        .iter()
                        .find_map(|op| match &op.command {
                            Command::PreparePayment {
                                ticket, material, ..
                            }
                            | Command::PrepareClaim {
                                ticket, material, ..
                            } if ticket.id == id => Some(material.clone()),
                            _ => None,
                        })
                })
                .context("retained preparation material")?;
            let m: Material = decode(&born.0, rld_protocol::MAX_CAPSULE)?;
            let terminal = Terminal {
                currency: c.configuration.currency,
                controller: id,
                initial: rld_protocol::codec::hash("RLD-CONTROLLER", c.configuration.currency, c),
                source_checkpoint: creation.source.header.id(),
                decision: 1,
                ticket_or_return: c.ticket.digest(c.configuration.currency),
                material_root: c.material_root,
            };
            proof::ControllerWitness {
                currency: s.node.core.initial.currency.clone(),
                creation,
                terminal,
                material: born,
                covers: m.covers,
                cancellation_authorization: None,
            }
        };
        let receipt = run_prover(exe, work, serial, "controller", &encode(&witness)).await?;
        let release = Release {
            creation: witness.creation,
            terminal: witness.terminal,
            receipt,
            qc: Quorum { votes: vec![] },
            covers: witness.covers,
            material: witness.material,
        };
        shared
            .lock()
            .map_err(|_| anyhow::anyhow!("node unavailable"))?
            .node
            .queue_candidate(rld_protocol::consensus::Payload::Export(release))?;
    }
    Ok(())
}
async fn run_prover(
    exe: &Path,
    work: &Path,
    _serial: u64,
    kind: &str,
    bytes: &[u8],
) -> Result<Blob> {
    let id = Id::digest(bytes);
    let input = work.join(format!("{kind}-{id}.input.cbor"));
    let output = work.join(format!("{kind}-{id}.receipt.cbor"));
    if output.exists() {
        return decode(
            &read_bounded(&output, rld_protocol::MAX_RECEIPT + 128)?,
            rld_protocol::MAX_RECEIPT + 128,
        );
    }
    if input.exists() {
        ensure!(
            read_bounded(&input, crate::store::MAX_RECORD)? == bytes,
            "different retained proving input"
        )
    } else {
        private_create(&input, bytes)?;
    }
    let mut process = tokio::process::Command::new(exe)
        .arg(kind)
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .env_remove("RISC0_DEV_MODE")
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    async fn bounded_log(mut input: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
        use tokio::io::AsyncReadExt;
        let mut buffer = [0u8; 8192];
        let mut kept = Vec::new();
        loop {
            let n = input.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            let take = n.min((64 * 1024usize).saturating_sub(kept.len()));
            kept.extend_from_slice(&buffer[..take]);
        }
        Ok(kept)
    }
    let stdout = process.stdout.take().context("prover stdout")?;
    let stderr = process.stderr.take().context("prover stderr")?;
    let (status, out, err) = tokio::join!(process.wait(), bounded_log(stdout), bounded_log(stderr));
    let status = status?;
    let out = out?;
    let err = err?;
    if !status.success() {
        let path = work.join(format!("{kind}-{id}-failure.log"));
        if !path.exists() {
            let mut log = out;
            log.extend_from_slice(&err);
            private_create(&path, &log)?;
        }
        anyhow::bail!(
            "prover failed; bounded diagnostic retained at {}",
            path.display()
        )
    }
    decode(
        &read_bounded(&output, rld_protocol::MAX_RECEIPT + 128)?,
        rld_protocol::MAX_RECEIPT + 128,
    )
}
