//! Pinned ground TLS and bounded frames. No ledger or durable custody authority.
use crate::{contact_crypto as crypto, require, wallet_client as files, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, PKCS_ED25519};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    ClientConfig, ClientConnection, Connection, DigitallySignedStruct, ProtocolVersion,
    ServerConfig, ServerConnection, SignatureScheme, Stream,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Cursor, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddrV4, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use x509_parser::prelude::*;
use zeroize::Zeroizing;

const FORMAT: &str = "RLD-NATIVE-CONTACT-TLS-V1";
const MAX_WIRE: usize = 20 * 1024 * 1024 + 4096;
// Existing 64-node / two inbound + one serial outbound limits, process-local.
const MAX_CONTEXTS: usize = 64;
const MAX_CONNECTIONS: usize = 192;
const SEED_PREFIX: &[u8] = &[
    0x30, 0x2e, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 0x22, 4, 0x20,
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Request {
    Info,
    Usage,
    Material {
        root: PathBuf,
        network: String,
        peer: String,
    },
    Context {
        root: PathBuf,
        network: String,
        peer: String,
    },
    ContextClose {
        handle: u64,
    },
    Accept {
        context: u64,
        fd: i32,
        deadline: f64,
    },
    Connect {
        host: String,
        port: u16,
        fingerprint: String,
        network: String,
        peer: String,
        deadline: f64,
    },
    Handshake {
        handle: u64,
    },
    Send {
        handle: u64,
        value: Value,
        deadline: f64,
    },
    Receive {
        handle: u64,
        deadline: f64,
    },
    Version {
        handle: u64,
    },
    Cipher {
        handle: u64,
    },
    Shutdown {
        handle: u64,
    },
    Close {
        handle: u64,
    },
}

fn utc() -> Result<i64> {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    i64::try_from(time.as_secs()).map_err(|e| e.to_string())
}
fn cert_check<'a>(
    der: &'a [u8],
    network: &str,
    peer: &str,
    now: i64,
) -> Result<X509Certificate<'a>> {
    crypto::hex_bytes::<32>(network)?;
    crypto::hex_bytes::<32>(peer)?;
    require(der.len() <= 8192, "TLS certificate byte bound")?;
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| "TLS certificate encoding")?;
    require(rest.is_empty(), "TLS certificate trailing bytes")?;
    require(
        cert.validity().not_before.timestamp() <= now
            && now <= cert.validity().not_after.timestamp(),
        "ground TLS certificate outside validity; preserve evidence",
    )?;
    let names = cert
        .subject()
        .iter_common_name()
        .map(|v| v.as_str())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "TLS common name encoding")?;
    let units = cert
        .subject()
        .iter_organizational_unit()
        .map(|v| v.as_str())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| "TLS network name encoding")?;
    let ed = "1.3.101.112";
    require(
        cert.subject() == cert.issuer()
            && names == [peer]
            && units == [network]
            && cert.public_key().algorithm.algorithm.to_id_string() == ed
            && cert.public_key().algorithm.parameters.is_none()
            && cert.signature_algorithm.algorithm.to_id_string() == ed
            && cert.signature_algorithm.parameters.is_none()
            && cert.public_key().subject_public_key.unused_bits == 0
            && cert.public_key().subject_public_key.data.len() == 32,
        "TLS certificate identity/network or algorithm mismatch",
    )?;
    cert.verify_signature(None)
        .map_err(|_| "TLS certificate self-signature invalid")?;
    Ok(cert)
}
fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    let encoded = STANDARD.encode(der);
    let mut bytes = format!("-----BEGIN {label}-----\n").into_bytes();
    for chunk in encoded.as_bytes().chunks(64) {
        bytes.extend_from_slice(chunk);
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(format!("-----END {label}-----\n").as_bytes());
    bytes
}
fn generate(network: &str, peer: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *seed).map_err(|_| "TLS entropy unavailable")?;
    let mut secret = Zeroizing::new(SEED_PREFIX.to_vec());
    secret.extend_from_slice(&*seed);
    let der = PrivatePkcs8KeyDer::from(secret.to_vec());
    let key = Zeroizing::new(
        KeyPair::from_pkcs8_der_and_sign_algo(&der, &PKCS_ED25519)
            .map_err(|_| "TLS key creation refused")?,
    );
    let now = ASN1Time::now().to_datetime();
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(|e| e.to_string())?;
    params.not_before = now - Duration::from_secs(300);
    params.not_after = now + Duration::from_secs(90 * 86400);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, peer);
    params
        .distinguished_name
        .push(DnType::OrganizationalUnitName, network);
    params.is_ca = IsCa::ExplicitNoCa;
    let mut serial = [0u8; 20];
    getrandom::getrandom(&mut serial).map_err(|_| "TLS serial entropy unavailable")?;
    serial[0] &= 0x7f;
    serial[19] |= 1;
    params.serial_number = Some(serial.to_vec().into());
    let cert = params.self_signed(&*key).map_err(|e| e.to_string())?;
    let mut bytes = Zeroizing::new(pem("CERTIFICATE", cert.der()));
    bytes.extend_from_slice(&Zeroizing::new(pem("PRIVATE KEY", &secret)));
    Ok(bytes)
}
struct Material {
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    public: Value,
}
fn material(root: &Path, network: &str, peer: &str) -> Result<Material> {
    crypto::hex_bytes::<32>(network)?;
    crypto::hex_bytes::<32>(peer)?;
    crypto::private_root(root)?;
    let path = root.join("tcp-tls.private.pem");
    if !path.try_exists().map_err(|e| e.to_string())? {
        let raw = generate(network, peer)?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options.open(&path).map_err(|e| e.to_string())?;
        file.write_all(&raw).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::File::open(root)
            .and_then(|d| d.sync_all())
            .map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        require(
            fs::symlink_metadata(&path)
                .map_err(|e| e.to_string())?
                .nlink()
                == 1,
            "TLS private material hardlink refused",
        )?;
    }
    let raw = Zeroizing::new(files::private_read_with_limit(&path, 8192)?);
    let mut reader = Cursor::new(&*raw);
    let cert =
        match rustls_pemfile::read_one(&mut reader).map_err(|_| "TLS certificate PEM refused")? {
            Some(rustls_pemfile::Item::X509Certificate(cert)) => cert,
            _ => return Err("TLS certificate PEM order".into()),
        };
    let key = match rustls_pemfile::read_one(&mut reader).map_err(|_| "TLS private PEM refused")? {
        Some(rustls_pemfile::Item::Pkcs8Key(key)) => key,
        _ => return Err("TLS private PEM order".into()),
    };
    let mut canonical = Zeroizing::new(pem("CERTIFICATE", &cert));
    canonical.extend_from_slice(&Zeroizing::new(pem("PRIVATE KEY", key.secret_pkcs8_der())));
    require(
        *canonical == *raw,
        "TLS private material malformed; preserve file",
    )?;
    // Exact canonical RFC 8410 seed encoding emitted by the original Python writer.
    let secret = key.secret_pkcs8_der();
    require(
        secret.len() == 48 && secret.starts_with(SEED_PREFIX),
        "TLS private key algorithm/encoding mismatch",
    )?;
    let parsed = cert_check(&cert, network, peer, utc()?)?;
    let seed = Zeroizing::new(<[u8; 32]>::try_from(&secret[16..]).map_err(|_| "TLS seed length")?);
    let public = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    require(
        public.as_bytes().as_slice() == parsed.public_key().subject_public_key.data.as_ref(),
        "TLS private key/certificate mismatch",
    )?;
    let expires = parsed.validity().not_after.to_datetime();
    let public = json!({"path":path,"fingerprint":hex::encode(Sha256::digest(&cert)),
        "expires":format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",expires.year(),u8::from(expires.month()),expires.day(),expires.hour(),expires.minute(),expires.second())});
    Ok(Material {
        cert,
        key: PrivateKeyDer::Pkcs8(key),
        public,
    })
}

#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
    network: String,
    peer: String,
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let check = || -> Result<()> {
            require(
                Sha256::digest(cert).as_slice() == self.fingerprint,
                "TLS certificate pin mismatch; no fallback",
            )?;
            cert_check(
                cert,
                &self.network,
                &self.peer,
                i64::try_from(now.as_secs()).map_err(|e| e.to_string())?,
            )?;
            Ok(())
        };
        check().map_err(rustls::Error::General)?;
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS downgrade refused".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        require(
            signature.scheme == SignatureScheme::ED25519,
            "TLS signature scheme differs",
        )
        .map_err(rustls::Error::General)?;
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
fn remaining(deadline: f64) -> Result<Duration> {
    let now = crate::bft_tick_schedule::monotonic()?;
    require(
        deadline.is_finite() && deadline > 0.0,
        "TLS monotonic deadline invalid",
    )?;
    let left = deadline - now;
    require(
        left > 0.0,
        "TLS_TIMEOUT: local attempt timed out; retain evidence",
    )?;
    Duration::try_from_secs_f64(left).map_err(|_| "TLS monotonic deadline invalid".into())
}
fn admission(deadline: f64) -> Result<()> {
    let left = remaining(deadline)?;
    require(
        left.as_secs_f64() <= 3.0,
        "TLS attempt exceeds original three-second bound",
    )
}
fn io_error(error: io::Error) -> String {
    if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        format!("TLS_TIMEOUT: {error}")
    } else {
        format!("TLS_IO: {error}")
    }
}
struct Timed {
    socket: TcpStream,
    deadline: f64,
}
impl Read for Timed {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let time =
            remaining(self.deadline).map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;
        self.socket.set_read_timeout(Some(time))?;
        self.socket.read(bytes)
    }
}
impl Write for Timed {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let time =
            remaining(self.deadline).map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;
        self.socket.set_write_timeout(Some(time))?;
        self.socket.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}
struct Session {
    tls: Connection,
    io: Timed,
}
struct Handle {
    session: Mutex<Session>,
    interrupt: TcpStream,
}
#[derive(Default)]
struct Handles {
    next: u64,
    contexts: BTreeMap<u64, Arc<ServerConfig>>,
    connections: BTreeMap<u64, Arc<Handle>>,
}
static HANDLES: OnceLock<Mutex<Handles>> = OnceLock::new();
fn table() -> Result<std::sync::MutexGuard<'static, Handles>> {
    HANDLES
        .get_or_init(|| Mutex::new(Handles::default()))
        .lock()
        .map_err(|_| "TLS handle table poisoned".into())
}
fn id(table: &mut Handles) -> Result<u64> {
    table.next = table
        .next
        .checked_add(1)
        .ok_or("TLS handle counter exhausted")?;
    Ok(table.next)
}
fn retain(tls: Connection, socket: TcpStream, deadline: f64) -> Result<u64> {
    let interrupt = socket.try_clone().map_err(io_error)?;
    let handle = Arc::new(Handle {
        session: Mutex::new(Session {
            tls,
            io: Timed { socket, deadline },
        }),
        interrupt,
    });
    let mut table = table()?;
    require(
        table.connections.len() < MAX_CONNECTIONS,
        "TLS connection capacity",
    )?;
    let id = id(&mut table)?;
    table.connections.insert(id, handle);
    Ok(id)
}
fn connection(handle: u64) -> Result<Arc<Handle>> {
    table()?
        .connections
        .get(&handle)
        .cloned()
        .ok_or("TLS connection handle absent".into())
}
fn handshake(session: &mut Session) -> Result<()> {
    remaining(session.io.deadline)?;
    while session.tls.is_handshaking() {
        session.tls.complete_io(&mut session.io).map_err(io_error)?;
    }
    require(
        session.tls.protocol_version() == Some(ProtocolVersion::TLSv1_3),
        "TLS downgrade refused",
    )
}
fn frame_deadline(session: &Session, deadline: f64) -> Result<()> {
    require(
        deadline.is_finite() && deadline <= session.io.deadline,
        "TLS original attempt deadline cannot be rebased",
    )?;
    remaining(deadline)?;
    Ok(())
}
trait Duplex: Read + Write {}
impl<T: Read + Write> Duplex for T {}
fn stream<T>(
    session: &mut Session,
    work: impl FnOnce(&mut dyn Duplex) -> io::Result<T>,
) -> Result<T> {
    let Session { tls, io } = session;
    match tls {
        Connection::Client(client) => work(&mut Stream::new(client, io)),
        Connection::Server(server) => work(&mut Stream::new(server, io)),
    }
    .map_err(io_error)
}
fn server_config(material: Material) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![material.cert], material.key)
        .map_err(|e| e.to_string())?;
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}
pub(crate) fn execute(request: Request) -> Result<Value> {
    match request {
        Request::Info => Ok(
            json!({"format":FORMAT,"max_wire":MAX_WIRE,"max_contexts":MAX_CONTEXTS,"max_connections":MAX_CONNECTIONS,"attempt_seconds":3,"certificate_days":90,"tls":"TLSv1.3"}),
        ),
        Request::Usage => {
            let table = table()?;
            Ok(
                json!({"contexts":table.contexts.len(),"connections":table.connections.len(),"authority":false}),
            )
        }
        Request::Material {
            root,
            network,
            peer,
        } => Ok(material(&root, &network, &peer)?.public),
        Request::Context {
            root,
            network,
            peer,
        } => {
            let material = material(&root, &network, &peer)?;
            let public = material.public.clone();
            let config = server_config(material)?;
            let mut table = table()?;
            require(table.contexts.len() < MAX_CONTEXTS, "TLS context capacity")?;
            let id = id(&mut table)?;
            table.contexts.insert(id, config);
            Ok(json!({"handle":id,"material":public}))
        }
        Request::ContextClose { handle } => {
            table()?.contexts.remove(&handle);
            Ok(Value::Null)
        }
        Request::Accept {
            context,
            fd,
            deadline,
        } => {
            admission(deadline)?;
            let config = table()?
                .contexts
                .get(&context)
                .cloned()
                .ok_or("TLS context handle absent")?;
            // Duplicate only a trusted in-process connected IPv4 socket. Never own the caller's fd.
            #[cfg(unix)]
            let socket = {
                use std::os::fd::FromRawFd;
                require(fd >= 0, "TLS socket descriptor invalid")?;
                let copied = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
                require(copied >= 0, "TLS socket descriptor duplication refused")?;
                let socket = unsafe { TcpStream::from_raw_fd(copied) };
                require(
                    socket.peer_addr().map_err(io_error)?.is_ipv4(),
                    "TLS socket IPv4 required",
                )?;
                // Python timeout sockets are nonblocking; the duplicated socket needs timed native I/O.
                socket.set_nonblocking(false).map_err(io_error)?;
                socket
            };
            #[cfg(not(unix))]
            return Err("TLS native socket platform unsupported".into());
            let tls = Connection::Server(ServerConnection::new(config).map_err(|e| e.to_string())?);
            Ok(json!(retain(tls, socket, deadline)?))
        }
        Request::Connect {
            host,
            port,
            fingerprint,
            network,
            peer,
            deadline,
        } => {
            admission(deadline)?;
            require(port != 0, "TLS TCP port invalid")?;
            let ip: Ipv4Addr = host
                .parse()
                .map_err(|_| "TLS endpoint must be literal IPv4")?;
            require(ip.to_string() == host, "TLS endpoint noncanonical IPv4")?;
            let pinned = Pinned {
                fingerprint: crypto::hex_bytes::<32>(&fingerprint)?,
                network,
                peer,
            };
            crypto::hex_bytes::<32>(&pinned.network)?;
            crypto::hex_bytes::<32>(&pinned.peer)?;
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| e.to_string())?
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(pinned))
                .with_no_client_auth();
            config.resumption = rustls::client::Resumption::disabled();
            config.enable_early_data = false;
            let tls = ClientConnection::new(Arc::new(config), ServerName::IpAddress(ip.into()))
                .map_err(|e| e.to_string())?;
            let socket = TcpStream::connect_timeout(
                &SocketAddrV4::new(ip, port).into(),
                remaining(deadline)?,
            )
            .map_err(io_error)?;
            let mut session = Session {
                tls: Connection::Client(tls),
                io: Timed { socket, deadline },
            };
            handshake(&mut session)?;
            Ok(json!(retain(session.tls, session.io.socket, deadline)?))
        }
        Request::Handshake { handle } => {
            let handle = connection(handle)?;
            let mut session = handle.session.lock().map_err(|_| "TLS session poisoned")?;
            handshake(&mut session)?;
            Ok(Value::Null)
        }
        Request::Version { handle } => {
            let handle = connection(handle)?;
            let session = handle.session.lock().map_err(|_| "TLS session poisoned")?;
            Ok(
                if !session.tls.is_handshaking()
                    && session.tls.protocol_version() == Some(ProtocolVersion::TLSv1_3)
                {
                    json!("TLSv1.3")
                } else {
                    Value::Null
                },
            )
        }
        Request::Cipher { handle } => {
            let handle = connection(handle)?;
            let session = handle.session.lock().map_err(|_| "TLS session poisoned")?;
            Ok(session
                .tls
                .negotiated_cipher_suite()
                .map_or(Value::Null, |suite| json!(format!("{:?}", suite.suite()))))
        }
        Request::Send {
            handle,
            value,
            deadline,
        } => {
            let raw = files::canonical_with_limit(&value, MAX_WIRE)?;
            require(!raw.is_empty(), "TCP wire byte bound; retain evidence")?;
            let handle = connection(handle)?;
            let mut session = handle.session.lock().map_err(|_| "TLS session poisoned")?;
            frame_deadline(&session, deadline)?;
            session.io.deadline = deadline;
            handshake(&mut session)?;
            stream(&mut session, |stream| {
                stream.write_all(&(raw.len() as u32).to_be_bytes())?;
                for part in raw.chunks(65536) {
                    remaining(deadline).map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;
                    stream.write_all(part)?;
                }
                stream.flush()
            })?;
            Ok(Value::Null)
        }
        Request::Receive { handle, deadline } => {
            let handle = connection(handle)?;
            let mut session = handle.session.lock().map_err(|_| "TLS session poisoned")?;
            frame_deadline(&session, deadline)?;
            session.io.deadline = deadline;
            handshake(&mut session)?;
            let mut prefix = [0; 4];
            stream(&mut session, |stream| stream.read_exact(&mut prefix))?;
            let len = u32::from_be_bytes(prefix) as usize;
            require(
                len > 0 && len <= MAX_WIRE,
                "TCP wire byte bound; retain evidence",
            )?;
            let mut raw = vec![0; len];
            stream(&mut session, |stream| {
                for part in raw.chunks_mut(65536) {
                    remaining(deadline).map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?;
                    stream.read_exact(part)?;
                }
                Ok(())
            })?;
            let value = crate::wallet_http::decode_unique_with_limit(&raw, MAX_WIRE)?;
            require(
                files::canonical_with_limit(&value, MAX_WIRE)? == raw,
                "TCP frame noncanonical; retain evidence",
            )?;
            Ok(value)
        }
        Request::Shutdown { handle } => {
            connection(handle)?
                .interrupt
                .shutdown(Shutdown::Both)
                .map_err(io_error)?;
            Ok(Value::Null)
        }
        Request::Close { handle } => {
            let handle = table()?.connections.remove(&handle);
            if let Some(handle) = handle {
                let _ = handle.interrupt.shutdown(Shutdown::Both);
            }
            Ok(Value::Null)
        }
    }
}
