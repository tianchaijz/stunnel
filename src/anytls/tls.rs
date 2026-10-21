use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{io, path::Path, sync::Arc};
use tokio_rustls::TlsConnector;

pub(crate) const ALPN: &[u8] = b"stunnel-anytls/1";

fn identity(
    cert: &Path,
    key: &Path,
) -> io::Result<(
    CertificateDer<'static>,
    PrivateKeyDer<'static>,
    rustls::RootCertStore,
)> {
    let cert = CertificateDer::from_pem_file(cert).map_err(io::Error::other)?;
    let key = PrivateKeyDer::from_pem_file(key).map_err(io::Error::other)?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).map_err(io::Error::other)?;
    Ok((cert, key, roots))
}

pub(super) fn client(cert: &Path, key: &Path) -> io::Result<TlsConnector> {
    let (cert, key, roots) = identity(cert, key)?;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_client_auth_cert(vec![cert], key)
    .map_err(io::Error::other)?;
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}
