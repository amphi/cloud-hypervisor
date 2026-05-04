// Copyright © 2026 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//

//! TLS support for migration streams over TCP.
//!
//! This module wraps `rustls` to provide a blocking [`TlsStream`] for migration
//! traffic. [`TlsStream::new_client`] authenticates the server against
//! `ca-cert.pem` and the expected hostname. If `client-cert.pem` and
//! `client-key.pem` are present, the client can present them for mutual TLS
//! (mTLS) authentication. [`TlsServerConfig`] loads `server-cert.pem` and
//! `server-key.pem`, and trusts client certificates issued by the CA in
//! `ca-cert.pem` when that CA file is present. [`TlsStream::new_server`] uses
//! that configuration to establish the server side of the connection.
//!
//! [`TlsStream`] implements [`Read`], [`Write`], [`ReadVolatile`],
//! [`WriteVolatile`], and [`AsFd`] so it can be used by the transport layer like
//! other migration streams. All data must pass through rustls; direct I/O on the
//! underlying socket would bypass TLS processing and break the connection.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::result;
use std::sync::Arc;

use log::info;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName};
use rustls::server::{VerifierBuilderError, WebPkiClientVerifier};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use thiserror::Error;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::{ReadVolatile, VolatileMemoryError, VolatileSlice, WriteVolatile};

use crate::MigratableError;

const CA_CERT_FILE: &str = "ca-cert.pem";
const CLIENT_CERT_FILE: &str = "client-cert.pem";
const CLIENT_KEY_FILE: &str = "client-key.pem";
const SERVER_CERT_FILE: &str = "server-cert.pem";
const SERVER_KEY_FILE: &str = "server-key.pem";

/// Errors that can occur when establishing a TLS-encrypted migration channel.
#[derive(Error, Debug)]
pub enum TlsError {
    #[error("The provided hostname could not be parsed")]
    InvalidDnsName(#[source] InvalidDnsNameError),

    #[error("Rustls protocol error")]
    RustlsError(#[from] rustls::Error),

    #[error("Rustls verifier configuration error")]
    RustlsVerifierBuilderError(#[source] VerifierBuilderError),

    #[error("Rustls protocol IO error")]
    RustlsIoError(#[from] std::io::Error),

    #[error("TLS handshake stalled: no read/write progress while handshake is still in progress")]
    HandshakeError,

    #[error("Error handling PEM file")]
    RustlsPemError(#[from] rustls::pki_types::pem::Error),

    #[error(
        "Incomplete TLS client authentication configuration: expected both {cert_path:?} and {key_path:?} to exist, or neither"
    )]
    IncompleteClientAuthConfig {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
}

/// Wraps the concrete rustls stream for either side (server or client) of the
/// TLS connection.
///
/// [`TlsStream`] uses this enum to store a [`StreamOwned`] with either a
/// [`ClientConnection`] or [`ServerConnection`] while exposing a single
/// transport-agnostic API.
#[derive(Debug)]
enum TlsStreamParticipant {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

/// Server/Client-agnostic TLS stream.
pub struct TlsStream {
    stream: TlsStreamParticipant,
    // We have to implement [`ReadVolatile`] and [`WriteVolatile`] for
    // [`TlsStream`]. We use this buffer to avoid allocating a new buffer for
    // every volatile read or write.
    buf: Vec<u8>,
}

impl TlsStream {
    /// The maximum size of [`TlsStream::buf`]. This keeps the reusable buffer
    /// from growing without bound.
    const BUF_SIZE: usize = 64 /* KiB */ << 10;

    /// Creates a client [`TlsStream`].
    ///
    /// The client verifies the server certificate against `ca-cert.pem` and the
    /// provided `hostname`. If `client-cert.pem` and `client-key.pem` are
    /// present, it can also present them for mutual TLS authentication.
    pub fn new_client(
        socket: TcpStream,
        cert_dir: &Path,
        hostname: &str,
    ) -> result::Result<Self, MigratableError> {
        let root_store = load_root_store(&cert_dir.join(CA_CERT_FILE))?;
        let client_auth_config = client_auth_config(cert_dir)?;
        let config_builder = ClientConfig::builder().with_root_certificates(root_store);
        let (config, mtls) = match client_auth_config {
            ClientAuthConfig::MutualTls {
                cert_path,
                key_path,
            } => {
                let client_certs = load_cert_chain(&cert_path)?;
                let client_key = load_private_key(&key_path)?;
                let config = config_builder
                    .with_client_auth_cert(client_certs, client_key)
                    .map_err(TlsError::RustlsError)
                    .map_err(MigratableError::Tls)?;

                (config, true)
            }
            ClientAuthConfig::NormalTls => (config_builder.with_no_client_auth(), false),
        };
        info!(
            "Using {} for migration client connection",
            if mtls { "mTLS" } else { "normal TLS" }
        );
        let config = Arc::new(config);

        let server_name = ServerName::try_from(hostname.to_string())
            .map_err(TlsError::InvalidDnsName)
            .map_err(MigratableError::Tls)?;
        let conn = ClientConnection::new(config.clone(), server_name.clone())
            .map_err(TlsError::RustlsError)
            .map_err(MigratableError::Tls)?;

        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            let (rd, wr) = tls
                .conn
                .complete_io(&mut tls.sock)
                .map_err(TlsError::RustlsIoError)
                .map_err(MigratableError::Tls)?;
            // No handshake progress on a connection that should be handshaking, we treat
            // that as a failure.
            if rd == 0 && wr == 0 {
                Err(MigratableError::Tls(TlsError::HandshakeError))?;
            }
        }

        Ok(Self {
            stream: TlsStreamParticipant::Client(tls),
            buf: Vec::new(),
        })
    }

    /// Creates a server [`TlsStream`]. Encrypts and decrypts data sent through
    /// this stream using the certificates and key from the provided
    /// [`TlsServerConfig`].
    pub fn new_server(
        socket: TcpStream,
        config: &TlsServerConfig,
    ) -> result::Result<Self, MigratableError> {
        let conn = ServerConnection::new(config.config.clone())
            .map_err(TlsError::RustlsError)
            .map_err(MigratableError::Tls)?;

        let mut tls = StreamOwned::new(conn, socket);
        while tls.conn.is_handshaking() {
            let (rd, wr) = tls
                .conn
                .complete_io(&mut tls.sock)
                .map_err(TlsError::RustlsIoError)
                .map_err(MigratableError::Tls)?;
            // No handshake progress on a connection that should be handshaking, we treat
            // that as a failure.
            if rd == 0 && wr == 0 {
                Err(MigratableError::Tls(TlsError::HandshakeError))?;
            }
        }

        Ok(Self {
            stream: TlsStreamParticipant::Server(tls),
            buf: Vec::new(),
        })
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.stream {
            TlsStreamParticipant::Client(s) => Read::read(s, buf),
            TlsStreamParticipant::Server(s) => Read::read(s, buf),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.stream {
            TlsStreamParticipant::Client(s) => Write::write(s, buf),
            TlsStreamParticipant::Server(s) => Write::write(s, buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.stream {
            TlsStreamParticipant::Client(s) => Write::flush(s),
            TlsStreamParticipant::Server(s) => Write::flush(s),
        }
    }
}

// Reading from or writing to these FDs would break the connection, because
// those reads or writes wouldn't go through rustls. But the FD is necessary to
// listen for incoming connections.
impl AsFd for TlsStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match &self.stream {
            TlsStreamParticipant::Client(s) => s.get_ref().as_fd(),
            TlsStreamParticipant::Server(s) => s.get_ref().as_fd(),
        }
    }
}

impl ReadVolatile for TlsStream {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        vs: &mut VolatileSlice<B>,
    ) -> result::Result<usize, VolatileMemoryError> {
        let len = vs.len().min(Self::BUF_SIZE);

        if len == 0 {
            return Ok(0);
        }

        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }

        let n = {
            let (stream, buf) = (&mut self.stream, &mut self.buf[..len]);

            match stream {
                TlsStreamParticipant::Client(s) => Read::read(s, buf),
                TlsStreamParticipant::Server(s) => Read::read(s, buf),
            }
            .map_err(VolatileMemoryError::IOError)?
        };

        if n == 0 {
            return Ok(0);
        }

        vs.copy_from(&self.buf[..n]);
        self.buf.clear();
        Ok(n)
    }
}

impl WriteVolatile for TlsStream {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        vs: &VolatileSlice<B>,
    ) -> Result<usize, VolatileMemoryError> {
        let len = vs.len().min(Self::BUF_SIZE);

        if len == 0 {
            return Ok(0);
        }

        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }

        let buf = &mut self.buf[..len];
        let n = vs.copy_to(&mut buf[..len]);

        if n == 0 {
            return Ok(0);
        }

        let n = {
            let stream = &mut self.stream;

            match stream {
                TlsStreamParticipant::Client(s) => Write::write(s, buf),
                TlsStreamParticipant::Server(s) => Write::write(s, buf),
            }
            .map_err(VolatileMemoryError::IOError)?
        };

        self.buf.clear();
        Ok(n)
    }
}

/// Carries a server-TLS-config. Intended to be turned into a [`TlsStream`]
/// when paired with a [`TcpStream`].
#[derive(Debug, Clone)]
pub struct TlsServerConfig {
    /// This config is shared between all server connections.
    config: Arc<ServerConfig>,
}

impl TlsServerConfig {
    /// Creates a [`TlsServerConfig`] from the certificate chain in
    /// `server-cert.pem` and the private key in `server-key.pem`.
    ///
    /// If `ca-cert.pem` is present, client certificates presented during the TLS
    /// handshake must chain to that CA.
    pub fn new(cert_dir: &Path) -> result::Result<Self, MigratableError> {
        let server_certs = load_cert_chain(&cert_dir.join(SERVER_CERT_FILE))?;
        let server_key = load_private_key(&cert_dir.join(SERVER_KEY_FILE))?;
        let ca_cert_path = cert_dir.join(CA_CERT_FILE);
        let config_builder = ServerConfig::builder();
        let (config_builder, mtls) = if ca_cert_path.is_file() {
            let client_roots = Arc::new(load_root_store(&ca_cert_path)?);
            let client_verifier = WebPkiClientVerifier::builder(client_roots)
                .build()
                .map_err(TlsError::RustlsVerifierBuilderError)
                .map_err(MigratableError::Tls)?;

            (
                config_builder.with_client_cert_verifier(client_verifier),
                true,
            )
        } else {
            (config_builder.with_no_client_auth(), false)
        };
        let config = config_builder
            .with_single_cert(server_certs, server_key)
            .map_err(TlsError::RustlsError)
            .map_err(MigratableError::Tls)?;
        info!(
            "Using {} for migration server connection",
            if mtls { "mTLS" } else { "normal TLS" }
        );
        let config = Arc::new(config);
        Ok(Self { config })
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ClientAuthConfig {
    MutualTls {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    NormalTls,
}

fn client_auth_config(cert_dir: &Path) -> result::Result<ClientAuthConfig, MigratableError> {
    let cert_path = cert_dir.join(CLIENT_CERT_FILE);
    let key_path = cert_dir.join(CLIENT_KEY_FILE);

    match (cert_path.is_file(), key_path.is_file()) {
        (true, true) => Ok(ClientAuthConfig::MutualTls {
            cert_path,
            key_path,
        }),
        (false, false) => Ok(ClientAuthConfig::NormalTls),
        _ => Err(MigratableError::Tls(TlsError::IncompleteClientAuthConfig {
            cert_path,
            key_path,
        })),
    }
}

/// Loads trusted CA certificates into a root store, i.e. the set of trust anchors
/// used to verify the peer's certificate chain.
fn load_root_store(cert_path: &Path) -> result::Result<RootCertStore, MigratableError> {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(cert_path)
            .map_err(TlsError::RustlsPemError)
            .map_err(MigratableError::Tls)?
            .map(|cert| cert.map_err(TlsError::RustlsPemError))
            .collect::<Result<Vec<CertificateDer<'static>>, TlsError>>()
            .map_err(MigratableError::Tls)?,
    );
    Ok(root_store)
}

/// Loads a certificate chain to present during the TLS handshake.
fn load_cert_chain(
    cert_path: &Path,
) -> result::Result<Vec<CertificateDer<'static>>, MigratableError> {
    CertificateDer::pem_file_iter(cert_path)
        .map_err(TlsError::RustlsPemError)
        .map_err(MigratableError::Tls)?
        .map(|cert| cert.map_err(TlsError::RustlsPemError))
        .collect::<Result<Vec<CertificateDer<'static>>, TlsError>>()
        .map_err(MigratableError::Tls)
}

/// Loads the private key that proves ownership of the presented certificate chain.
fn load_private_key(key_path: &Path) -> result::Result<PrivateKeyDer<'static>, MigratableError> {
    PrivateKeyDer::from_pem_file(key_path)
        .map_err(TlsError::RustlsPemError)
        .map_err(MigratableError::Tls)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cloud-hypervisor-tls-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn client_auth_config_uses_normal_tls_without_client_credentials() {
        let dir = temp_test_dir("no-client-credentials");

        assert_eq!(
            client_auth_config(&dir).unwrap(),
            ClientAuthConfig::NormalTls
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn client_auth_config_uses_mtls_with_client_credentials() {
        let dir = temp_test_dir("client-credentials");
        let cert_path = dir.join(CLIENT_CERT_FILE);
        let key_path = dir.join(CLIENT_KEY_FILE);
        fs::write(&cert_path, "").unwrap();
        fs::write(&key_path, "").unwrap();

        assert_eq!(
            client_auth_config(&dir).unwrap(),
            ClientAuthConfig::MutualTls {
                cert_path,
                key_path
            }
        );

        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn client_auth_config_rejects_partial_client_credentials() {
        let dir = temp_test_dir("partial-client-credentials");
        fs::write(dir.join(CLIENT_CERT_FILE), "").unwrap();

        assert!(matches!(
            client_auth_config(&dir),
            Err(MigratableError::Tls(
                TlsError::IncompleteClientAuthConfig { .. }
            ))
        ));

        fs::remove_dir_all(dir).unwrap();
    }
}
