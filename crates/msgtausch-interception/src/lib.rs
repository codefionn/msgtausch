//! TLS certificate issuance and stream setup for HTTPS interception.

use std::{
    collections::{HashMap, VecDeque},
    fs,
    sync::{Arc, Mutex},
};

use aes::{
    Aes128, Aes192, Aes256,
    cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7},
};
use anyhow::{Context, Result, bail};
use compio::{
    net::TcpStream,
    tls::{TlsConnector, TlsStream},
};
use des::Des;
use futures_rustls::{TlsAcceptor as FuturesTlsAcceptor, server::TlsStream as ServerTlsStream};
use md5::{Digest, Md5};
use pkcs8::{
    AlgorithmIdentifierRef, EncryptedPrivateKeyInfo, ObjectIdentifier, PrivateKeyInfo,
    der::{SecretDocument, asn1::AnyRef, pem::LineEnding},
};
use rcgen::{CertificateParams, Issuer, KeyPair};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, pki_types::CertificateDer, sign::CertifiedKey,
};

use msgtausch_config::{Classifier, InterceptionConfig};
use msgtausch_policy::{ClassifierEngine, Target};

const LEAF_CACHE_CAPACITY: usize = 256;

/// Immutable interception state. It is absent when interception is disabled,
/// so normal CONNECT tunnelling does not pay for certificate machinery.
#[derive(Clone)]
pub struct InterceptionRuntime {
    issuer: Arc<Issuer<'static, KeyPair>>,
    leaves: Arc<Mutex<LeafCache>>,
    upstream: TlsConnector,
    upstream_config: Arc<ClientConfig>,
    https_classifier: Option<Classifier>,
    exclude_classifier: Option<Classifier>,
}

impl InterceptionRuntime {
    /// Load the configured CA and construct the verified upstream TLS client.
    /// Encrypted keys require `ca-key-passwd`; plaintext keys remain valid
    /// when a password is configured for compatibility with older deployments.
    pub fn from_config(config: &InterceptionConfig) -> Result<Option<Self>> {
        Self::from_config_for_dedicated_listener(config, false)
    }

    /// Load CA state for a dedicated HTTPS or HTTP/3 listener even when
    /// standard CONNECT interception is off. The caller still owns policy.
    pub fn from_config_for_dedicated_listener(
        config: &InterceptionConfig,
        dedicated_listener: bool,
    ) -> Result<Option<Self>> {
        if !dedicated_listener && (!config.enabled || !config.https) {
            return Ok(None);
        }
        let cert_path = config
            .ca_file
            .as_ref()
            .context("HTTPS/QUIC listener requires interception.ca-file")?;
        let key_path = config
            .ca_key_file
            .as_ref()
            .context("HTTPS/QUIC listener requires interception.ca-key-file")?;
        let cert = fs::read_to_string(cert_path).with_context(|| {
            format!(
                "reading interception CA certificate {}",
                cert_path.display()
            )
        })?;
        let key = fs::read_to_string(key_path)
            .with_context(|| format!("reading interception CA key {}", key_path.display()))?;
        let key = decrypt_ca_key(&key, config.ca_key_passwd.as_deref())?;
        let key = KeyPair::from_pem(&key).context("parsing interception CA key")?;
        let issuer =
            Issuer::from_ca_cert_pem(&cert, key).context("parsing interception CA certificate")?;

        let upstream_config = Arc::new(upstream_config(config.insecure_skip_verify)?);
        Ok(Some(Self {
            issuer: Arc::new(issuer),
            leaves: Arc::new(Mutex::new(LeafCache::default())),
            upstream: TlsConnector::from(upstream_config.clone()),
            upstream_config,
            https_classifier: config.https_classifier.clone(),
            exclude_classifier: config.exclude_classifier.clone(),
        }))
    }

    /// Whether a CONNECT target should be terminated locally.
    pub fn should_intercept(
        &self,
        target: &Target,
        classifiers: &ClassifierEngine,
    ) -> Result<bool> {
        if let Some(rule) = &self.exclude_classifier
            && classifiers.matches_config(rule, target)?
        {
            return Ok(false);
        }
        self.https_classifier
            .as_ref()
            .map(|rule| classifiers.matches_config(rule, target))
            .transpose()
            .map(|matched| matched.unwrap_or(true))
    }

    /// Start the downstream TLS handshake with a cached, host-specific leaf.
    pub async fn accept_downstream<S>(&self, stream: S, host: &str) -> Result<ServerTlsStream<S>>
    where
        S: futures_util::io::AsyncRead + futures_util::io::AsyncWrite + Unpin + Send + 'static,
    {
        let config = self.leaf_config(host)?;
        FuturesTlsAcceptor::from(config)
            .accept(stream)
            .await
            .context("accepting intercepted downstream TLS connection")
    }

    /// Return the dynamically-issued TLS server configuration for a hostname.
    /// HTTPS listeners use this after inspecting the ClientHello SNI.
    pub fn downstream_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        self.leaf_config(host)
    }

    /// TLS configuration shared by intercepted TCP and HTTP/3 upstreams.
    pub fn upstream_tls_config(&self) -> Arc<ClientConfig> {
        self.upstream_config.clone()
    }

    /// Build the QUIC server config whose certificate resolver signs a leaf
    /// for the ClientHello SNI. Missing SNI rejects the handshake.
    pub fn quic_server_config(&self) -> Arc<ServerConfig> {
        let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(QuicLeafResolver {
                runtime: self.clone(),
            }));
        config.alpn_protocols = vec![b"h3".to_vec()];
        config.max_early_data_size = 0;
        Arc::new(config)
    }

    /// Connect an intercepted request to its original host. The default config
    /// validates the system trust store and the requested DNS name or IP SAN.
    pub async fn connect_upstream(
        &self,
        stream: TcpStream,
        host: &str,
    ) -> Result<TlsStream<TcpStream>> {
        self.upstream
            .connect(host, stream)
            .await
            .with_context(|| format!("performing upstream TLS handshake for {host}"))
    }

    fn leaf_config(&self, host: &str) -> Result<Arc<ServerConfig>> {
        let certified = self.leaf(host)?;
        Ok(Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedLeafResolver(certified))),
        ))
    }

    fn leaf(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let mut cache = self
            .leaves
            .lock()
            .expect("interception leaf cache mutex poisoned");
        if let Some(certified) = cache.values.get(host).cloned() {
            cache.touch(host);
            return Ok(certified);
        }
        let params = CertificateParams::new(vec![host.to_owned()])
            .with_context(|| format!("creating certificate SAN for {host}"))?;
        let leaf_key = KeyPair::generate().context("generating intercepted leaf key")?;
        let certificate = params
            .signed_by(&leaf_key, &self.issuer)
            .context("signing intercepted leaf certificate")?;
        let certified = Arc::new(
            CertifiedKey::from_der(
                vec![certificate.der().clone()],
                leaf_key.into(),
                rustls::crypto::CryptoProvider::get_default()
                    .context("loading rustls crypto provider")?,
            )
            .context("building intercepted leaf signing key")?,
        );
        cache.insert(host.to_owned(), certified.clone());
        Ok(certified)
    }
}

#[derive(Debug)]
struct FixedLeafResolver(Arc<CertifiedKey>);
impl rustls::server::ResolvesServerCert for FixedLeafResolver {
    fn resolve(&self, _: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

struct QuicLeafResolver {
    runtime: InterceptionRuntime,
}
impl std::fmt::Debug for QuicLeafResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QuicLeafResolver")
    }
}
impl rustls::server::ResolvesServerCert for QuicLeafResolver {
    fn resolve(&self, hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.runtime.leaf(hello.server_name()?).ok()
    }
}

/// Decrypt the two supported PEM encryption formats. PKCS#8 is
/// the current format. RFC1423 is retained solely to let existing CA files
/// survive a migration; it uses obsolete MD5 and DES/AES-CBC construction.
fn decrypt_ca_key(key_pem: &str, password: Option<&str>) -> Result<String> {
    let block = pem::parse(key_pem).context("parsing interception CA key PEM")?;
    if block.tag() == "ENCRYPTED PRIVATE KEY" {
        let password =
            password.context("encrypted PKCS#8 interception CA key requires ca-key-passwd")?;
        let encrypted = EncryptedPrivateKeyInfo::try_from(block.contents()).map_err(|error| {
            anyhow::anyhow!("parsing encrypted PKCS#8 interception CA key: {error:?}")
        })?;
        let decrypted = encrypted.decrypt(password).map_err(|error| {
            anyhow::anyhow!("decrypting encrypted PKCS#8 interception CA key: {error:?}")
        })?;
        return Ok(pem::encode(&pem::Pem::new(
            "PRIVATE KEY",
            decrypted.as_bytes(),
        )));
    }
    if block.headers().get("Proc-Type") == Some("4,ENCRYPTED")
        || block.headers().get("DEK-Info").is_some()
    {
        let password =
            password.context("encrypted legacy interception CA key requires ca-key-passwd")?;
        let plaintext = decrypt_legacy_pem(&block, password)?;
        return encode_pkcs8(block.tag(), &plaintext);
    }
    match block.tag() {
        "EC PRIVATE KEY" | "RSA PRIVATE KEY" => encode_pkcs8(block.tag(), block.contents()),
        _ => Ok(key_pem.to_owned()),
    }
}

/// Ring only accepts PKCS#8 private keys. Preserve support for the SEC1 and
/// PKCS#1 files emitted by the Go implementation by wrapping their plaintext
/// DER in PKCS#8 after decryption.
fn encode_pkcs8(tag: &str, private_key: &[u8]) -> Result<String> {
    const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const RSA_ENCRYPTION_OID: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

    let curve_oid = match tag {
        "EC PRIVATE KEY" => {
            let key = sec1::EcPrivateKey::try_from(private_key)
                .map_err(|error| anyhow::anyhow!("parsing SEC1 interception CA key: {error:?}"))?;
            Some(
                key.parameters
                    .context("SEC1 interception CA key has no named curve parameters")?
                    .named_curve()
                    .context("SEC1 interception CA key does not use a named curve")?,
            )
        }
        _ => None,
    };
    let algorithm = match tag {
        "EC PRIVATE KEY" => AlgorithmIdentifierRef {
            oid: EC_PUBLIC_KEY_OID,
            parameters: Some(curve_oid.as_ref().expect("set above").into()),
        },
        "RSA PRIVATE KEY" => AlgorithmIdentifierRef {
            oid: RSA_ENCRYPTION_OID,
            parameters: Some(AnyRef::NULL),
        },
        _ => bail!("unsupported legacy interception CA key type {tag}"),
    };
    let key = PrivateKeyInfo::new(algorithm, private_key);
    let document = SecretDocument::encode_msg(&key)
        .map_err(|error| anyhow::anyhow!("encoding PKCS#8 CA key: {error:?}"))?;
    Ok(document
        .to_pem("PRIVATE KEY", LineEnding::LF)
        .map_err(|error| anyhow::anyhow!("encoding PKCS#8 CA key PEM: {error:?}"))?
        .to_string())
}

fn decrypt_legacy_pem(block: &pem::Pem, password: &str) -> Result<Vec<u8>> {
    if block.headers().get("Proc-Type") != Some("4,ENCRYPTED") {
        bail!("legacy interception CA key does not have Proc-Type: 4,ENCRYPTED");
    }
    let dek_info = block
        .headers()
        .get("DEK-Info")
        .context("legacy interception CA key has no DEK-Info header")?;
    let (algorithm, iv_hex) = dek_info
        .split_once(',')
        .context("legacy interception CA key has malformed DEK-Info")?;
    let iv = decode_hex(iv_hex).context("legacy interception CA key has invalid DEK-Info IV")?;
    let (key_length, iv_length) = match algorithm {
        "AES-128-CBC" => (16, 16),
        "AES-192-CBC" => (24, 16),
        "AES-256-CBC" => (32, 16),
        "DES-CBC" => (8, 8),
        _ => bail!("unsupported legacy interception CA key encryption algorithm {algorithm}"),
    };
    if iv.len() != iv_length {
        bail!(
            "legacy interception CA key IV has length {}, expected {iv_length}",
            iv.len()
        );
    }
    let key = evp_bytes_to_key(password.as_bytes(), &iv[..8], key_length);
    let mut ciphertext = block.contents().to_vec();
    let plaintext = match algorithm {
        "AES-128-CBC" => cbc::Decryptor::<Aes128>::new_from_slices(&key, &iv)
            .map_err(|_| anyhow::anyhow!("invalid AES-128-CBC key or IV"))?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
            .map_err(|_| anyhow::anyhow!("invalid legacy AES-128-CBC key password or padding"))?,
        "AES-192-CBC" => cbc::Decryptor::<Aes192>::new_from_slices(&key, &iv)
            .map_err(|_| anyhow::anyhow!("invalid AES-192-CBC key or IV"))?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
            .map_err(|_| anyhow::anyhow!("invalid legacy AES-192-CBC key password or padding"))?,
        "AES-256-CBC" => cbc::Decryptor::<Aes256>::new_from_slices(&key, &iv)
            .map_err(|_| anyhow::anyhow!("invalid AES-256-CBC key or IV"))?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
            .map_err(|_| anyhow::anyhow!("invalid legacy AES-256-CBC key password or padding"))?,
        "DES-CBC" => cbc::Decryptor::<Des>::new_from_slices(&key, &iv)
            .map_err(|_| anyhow::anyhow!("invalid DES-CBC key or IV"))?
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
            .map_err(|_| anyhow::anyhow!("invalid legacy DES-CBC key password or padding"))?,
        _ => unreachable!("validated above"),
    };
    Ok(plaintext.to_vec())
}

fn evp_bytes_to_key(password: &[u8], salt: &[u8], key_length: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(key_length);
    let mut previous = Vec::new();
    while output.len() < key_length {
        let mut digest = Md5::new();
        digest.update(&previous);
        digest.update(password);
        digest.update(salt);
        previous = digest.finalize().to_vec();
        output.extend_from_slice(&previous);
    }
    output.truncate(key_length);
    output
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        bail!("hex value has an odd length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => bail!("not a hex digit"),
    }
}

#[derive(Default)]
struct LeafCache {
    values: HashMap<String, Arc<CertifiedKey>>,
    lru: VecDeque<String>,
}

impl LeafCache {
    fn touch(&mut self, host: &str) {
        if let Some(position) = self.lru.iter().position(|entry| entry == host) {
            self.lru.remove(position);
        }
        self.lru.push_back(host.to_owned());
    }

    fn insert(&mut self, host: String, certified: Arc<CertifiedKey>) {
        self.values.insert(host.clone(), certified);
        self.touch(&host);
        while self.values.len() > LEAF_CACHE_CAPACITY {
            if let Some(oldest) = self.lru.pop_front() {
                self.values.remove(&oldest);
            }
        }
    }
}

fn upstream_config(insecure: bool) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for certificate in native.certs {
        roots
            .add(certificate)
            .context("adding a system trust root")?;
    }
    if roots.is_empty() {
        bail!("system trust store contains no certificates");
    }
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_root_certificates(roots)
        .with_no_client_auth();
    if insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));
    }
    Ok(config)
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let _ = (message, cert, dss);
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        let _ = (message, cert, dss);
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "testpassword";

    #[test]
    fn decrypts_legacy_encrypted_ca_key_fixtures() {
        let fixtures = [
            ("ec_aes128", include_str!("../testdata/ec_aes128.pem")),
            ("rsa_aes128", include_str!("../testdata/rsa_aes128.pem")),
            ("rsa_aes192", include_str!("../testdata/rsa_aes192.pem")),
            ("rsa_aes256", include_str!("../testdata/rsa_aes256.pem")),
            (
                "rsa_aes256_legacy",
                include_str!("../testdata/rsa_aes256_legacy.pem"),
            ),
        ];
        for (name, fixture) in fixtures {
            let decrypted = decrypt_ca_key(fixture, Some(PASSWORD)).expect("decrypt fixture");
            KeyPair::from_pem(&decrypted)
                .unwrap_or_else(|error| panic!("{name}: rcgen rejected decrypted key: {error}"));
        }
    }

    #[test]
    fn rejects_an_incorrect_password() {
        let fixture = include_str!("../testdata/rsa_aes256.pem");
        assert!(decrypt_ca_key(fixture, Some("incorrect")).is_err());
    }

    #[test]
    fn leaves_an_unencrypted_key_unchanged_when_a_password_is_set() {
        let fixture = include_str!("../testdata/rsa_unencrypted.pem");
        assert_eq!(decrypt_ca_key(fixture, Some(PASSWORD)).unwrap(), fixture);
    }

    #[test]
    fn decrypts_a_legacy_des_cbc_key() {
        use aes::cipher::{BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};

        let iv = [0x11; 8];
        let key = evp_bytes_to_key(PASSWORD.as_bytes(), &iv, 8);
        let mut encrypted = [0_u8; 16];
        encrypted[..4].copy_from_slice(b"key!");
        let ciphertext = cbc::Encryptor::<Des>::new_from_slices(&key, &iv)
            .unwrap()
            .encrypt_padded_mut::<Pkcs7>(&mut encrypted, 4)
            .unwrap()
            .to_vec();
        let mut block = pem::Pem::new("RSA PRIVATE KEY", ciphertext);
        block.headers_mut().add("Proc-Type", "4,ENCRYPTED").unwrap();
        block
            .headers_mut()
            .add("DEK-Info", "DES-CBC,1111111111111111")
            .unwrap();
        assert_eq!(decrypt_legacy_pem(&block, PASSWORD).unwrap(), b"key!");
    }
}
