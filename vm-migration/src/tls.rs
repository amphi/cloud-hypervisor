// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::fd::{AsFd, BorrowedFd};
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, PrivateKeyDer, ServerName};
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
};
use thiserror::Error;
use vm_memory::bitmap::BitmapSlice;
use vm_memory::io::{ReadVolatile, WriteVolatile};
use vm_memory::{VolatileMemoryError, VolatileSlice};

use crate::MigratableError;

#[derive(Error, Debug)]
pub enum TlsError {
    #[error(
        "The provided input could not be parsed because it is not a syntactically-valid DNS Name."
    )]
    InvalidDnsName(#[source] InvalidDnsNameError),

    #[error("Rustls protocol error")]
    RustlsError(#[from] rustls::Error),
}

// This TlsStream will be later encapsulated in a SocketStream. Thus it has to
// implement the same traits. It is important that we never directly read from
// or write to the TcpStream encapsulated in StreamOwned.
pub enum TlsStream {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            TlsStream::Client(s) => s.read(buf),
            TlsStream::Server(s) => s.read(buf),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            TlsStream::Client(s) => s.write(buf),
            TlsStream::Server(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            TlsStream::Client(s) => s.flush(),
            TlsStream::Server(s) => s.flush(),
        }
    }
}

// Let's pray that nobody tries to read from or write to these fds.
impl AsFd for TlsStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            TlsStream::Client(s) => s.get_ref().as_fd(),
            TlsStream::Server(s) => s.get_ref().as_fd(),
        }
    }
}

impl ReadVolatile for TlsStream {
    fn read_volatile<B: BitmapSlice>(
        &mut self,
        vs: &mut VolatileSlice<B>,
    ) -> std::result::Result<usize, VolatileMemoryError> {
        let mut tmp = vec![0u8; vs.len()];
        let n = Read::read(self, &mut tmp[..]).unwrap();
        vs.copy_from(&tmp[..n]);
        Ok(n)
    }
}

impl WriteVolatile for TlsStream {
    fn write_volatile<B: BitmapSlice>(
        &mut self,
        vs: &VolatileSlice<B>,
    ) -> std::result::Result<usize, VolatileMemoryError> {
        let mut tmp = vec![0u8; vs.len()];
        let n = vs.copy_to(&mut tmp[..]);
        let n = Write::write(self, &tmp[..n]).unwrap();
        Ok(n)
    }
}

// A small wrapper to be put into ReceiveListener::Tls. It carries the
// TLS-Config and creates a TlsStream after the TcpConnection accepted a
// connection.
#[derive(Debug, Clone)]
pub struct TlsConnectionWrapper {
    config: Arc<ServerConfig>,
}

impl TlsConnectionWrapper {
    pub fn new(cert_pem: &str, key_pem: &str) -> Self {
        let certs = CertificateDer::pem_file_iter(cert_pem.to_owned())
            .unwrap()
            .map(|cert| cert.unwrap())
            .collect();
        let key = PrivateKeyDer::from_pem_file(key_pem.to_owned()).unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(TlsError::RustlsError)
            .unwrap();
        let config = Arc::new(config);
        Self { config }
    }

    pub fn wrap(&self, socket: TcpStream) -> std::result::Result<TlsStream, MigratableError> {
        let conn = ServerConnection::new(self.config.clone()).map_err(TlsError::RustlsError)?;

        Ok(TlsStream::Server(StreamOwned::new(conn, socket)))
    }
}

pub fn client_stream(
    socket: TcpStream,
    cert_pem: &str,
    hostname: &str,
) -> std::result::Result<StreamOwned<ClientConnection, TcpStream>, MigratableError> {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(
        CertificateDer::pem_file_iter(cert_pem.to_owned())
            .expect("Cannot open CA file")
            .map(|result| result.unwrap()),
    );
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let config = Arc::new(config);
    let server_name = ServerName::try_from(hostname.to_string())
        .map_err(|e| MigratableError::Tls(TlsError::InvalidDnsName(e)))?;
    let conn = ClientConnection::new(config.clone(), server_name.clone())
        .map_err(|e| MigratableError::Tls(TlsError::RustlsError(e)))
        .unwrap();
    Ok(StreamOwned::new(conn, socket))
}
