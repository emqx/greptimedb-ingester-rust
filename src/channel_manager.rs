// Copyright 2023 Greptime Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::io::BufReader;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use lazy_static::lazy_static;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use snafu::{OptionExt, ResultExt};
use tokio_util::sync::CancellationToken;
use tonic::codec::CompressionEncoding;
use tonic::transport::{Certificate, ClientTlsConfig, Identity};
use tonic::transport::{Channel as InnerChannel, Endpoint, Uri};
use tower::Service;

use crate::error::{CreateChannelSnafu, Result};
use crate::error::{InvalidConfigFilePathSnafu, InvalidTlsConfigSnafu};

const RECYCLE_CHANNEL_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_GRPC_REQUEST_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_GRPC_CONNECT_TIMEOUT_SECS: u64 = 1;
pub const DEFAULT_MAX_GRPC_RECV_MESSAGE_SIZE: u64 = 512 * 1024 * 1024;
pub const DEFAULT_MAX_GRPC_SEND_MESSAGE_SIZE: u64 = 512 * 1024 * 1024;

lazy_static! {
    static ref ID: AtomicU64 = AtomicU64::new(0);
}

#[derive(Clone, Debug, Default)]
pub struct ChannelManager {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    id: u64,
    config: ChannelConfig,
    client_tls_config: Option<ClientTlsConfig>,
    pool: Arc<Pool>,
    channel_recycle_started: AtomicBool,
    cancel: CancellationToken,
}

impl Default for Inner {
    fn default() -> Self {
        Self::with_config(ChannelConfig::default())
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        // Cancel the channel recycle task.
        self.cancel.cancel();
    }
}

impl Inner {
    fn with_config(config: ChannelConfig) -> Self {
        let id = ID.fetch_add(1, Ordering::Relaxed);
        let pool = Arc::new(Pool::default());
        let cancel = CancellationToken::new();

        Self {
            id,
            config,
            client_tls_config: None,
            pool,
            channel_recycle_started: AtomicBool::new(false),
            cancel,
        }
    }
}

impl ChannelManager {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn id(&self) -> u64 {
        self.inner.id
    }

    pub fn with_config(config: ChannelConfig) -> Self {
        let inner = Inner::with_config(config);
        Self {
            inner: Arc::new(inner),
        }
    }
    pub fn with_tls_config(config: ChannelConfig) -> Result<Self> {
        ensure_default_crypto_provider();
        let mut inner = Inner::with_config(config.clone());

        // setup tls
        let path_config = config.client_tls.context(InvalidTlsConfigSnafu {
            msg: "no config input",
        })?;

        let mut tls_config = ClientTlsConfig::new().with_enabled_roots();

        if config.tls_verify == TlsVerify::VerifyPeer && !path_config.server_ca_cert_path.is_empty()
        {
            let server_root_ca_cert = std::fs::read_to_string(path_config.server_ca_cert_path)
                .context(InvalidConfigFilePathSnafu)?;
            let server_root_ca_cert = Certificate::from_pem(server_root_ca_cert);
            tls_config = tls_config.ca_certificate(server_root_ca_cert);
        }

        let has_client_cert = !path_config.client_cert_path.is_empty();
        let has_client_key = !path_config.client_key_path.is_empty();
        if has_client_cert != has_client_key {
            return InvalidTlsConfigSnafu {
                msg: "client cert and key must be configured together".to_string(),
            }
            .fail();
        }
        if has_client_cert {
            let client_cert = std::fs::read_to_string(path_config.client_cert_path)
                .context(InvalidConfigFilePathSnafu)?;
            let client_key = std::fs::read_to_string(path_config.client_key_path)
                .context(InvalidConfigFilePathSnafu)?;
            let client_identity = Identity::from_pem(client_cert, client_key);
            tls_config = tls_config.identity(client_identity);
        }

        inner.client_tls_config = Some(tls_config);

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub fn config(&self) -> &ChannelConfig {
        &self.inner.config
    }

    fn pool(&self) -> &Arc<Pool> {
        &self.inner.pool
    }

    pub fn get(&self, addr: impl AsRef<str>) -> Result<InnerChannel> {
        self.trigger_channel_recycling();

        let addr = addr.as_ref();
        // It will acquire the read lock.
        if let Some(inner_ch) = self.pool().get(addr) {
            return Ok(inner_ch);
        }

        // It will acquire the write lock.
        let entry = match self.pool().entry(addr.to_string()) {
            Entry::Occupied(entry) => {
                entry.get().increase_access();
                entry.into_ref()
            }
            Entry::Vacant(entry) => {
                let use_insecure_tls = self.use_insecure_tls();
                let has_custom_cipher = self.has_custom_cipher_requirement();
                let use_custom_tls = use_insecure_tls || has_custom_cipher;
                let endpoint = self.build_endpoint(addr, !use_custom_tls, use_custom_tls)?;
                let inner_channel = if use_custom_tls {
                    let connector = if use_insecure_tls {
                        self.build_insecure_https_connector()?
                    } else {
                        self.build_verified_https_connector_with_ciphers()?
                    };
                    endpoint.connect_with_connector_lazy(connector)
                } else {
                    endpoint.connect_lazy()
                };

                let channel = Channel {
                    channel: inner_channel,
                    access: AtomicUsize::new(1),
                    use_default_connector: !use_custom_tls,
                };
                entry.insert(channel)
            }
        };
        Ok(entry.channel.clone())
    }

    pub fn reset_with_connector<C>(
        &self,
        addr: impl AsRef<str>,
        connector: C,
    ) -> Result<InnerChannel>
    where
        C: Service<Uri> + Send + 'static,
        C::Response: hyper::rt::Read + hyper::rt::Write + Send + Unpin,
        C::Future: Send + 'static,
        Box<dyn std::error::Error + Send + Sync>: From<C::Error> + Send + 'static,
    {
        let addr = addr.as_ref();
        let endpoint = self.build_endpoint(addr, true, false)?;
        let inner_channel = endpoint.connect_with_connector_lazy(connector);
        let channel = Channel {
            channel: inner_channel.clone(),
            access: AtomicUsize::new(1),
            use_default_connector: false,
        };
        self.pool().put(addr, channel);

        Ok(inner_channel)
    }

    pub fn retain_channel<F>(&self, f: F)
    where
        F: FnMut(&String, &mut Channel) -> bool,
    {
        self.pool().retain_channel(f);
    }

    fn use_insecure_tls(&self) -> bool {
        self.inner.client_tls_config.is_some() && self.config().tls_verify == TlsVerify::VerifyNone
    }

    fn has_custom_cipher_requirement(&self) -> bool {
        if let Some(ref tls) = self.config().client_tls {
            !tls.cipher_suites.is_empty()
        } else {
            false
        }
    }

    fn build_insecure_https_connector(&self) -> Result<HttpsOverHttpConnector> {
        ensure_default_crypto_provider();
        let path_config = self
            .config()
            .client_tls
            .as_ref()
            .context(InvalidTlsConfigSnafu {
                msg: "no config input",
            })?;
        let tls_config = build_custom_client_tls_config(path_config, TlsVerify::VerifyNone)?;
        let inner = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http2()
            .build();
        Ok(HttpsOverHttpConnector { inner })
    }

    fn build_verified_https_connector_with_ciphers(&self) -> Result<HttpsOverHttpConnector> {
        ensure_default_crypto_provider();
        let path_config = self
            .config()
            .client_tls
            .as_ref()
            .context(InvalidTlsConfigSnafu {
                msg: "no config input",
            })?;
        let tls_config = build_custom_client_tls_config(path_config, TlsVerify::VerifyPeer)?;
        let inner = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_only()
            .enable_http2()
            .build();
        Ok(HttpsOverHttpConnector { inner })
    }

    fn build_endpoint(
        &self,
        addr: &str,
        apply_tonic_tls_config: bool,
        force_http_scheme: bool,
    ) -> Result<Endpoint> {
        let http_prefix = if force_http_scheme {
            "http"
        } else if self.inner.client_tls_config.is_some() {
            "https"
        } else {
            "http"
        };
        let mut endpoint =
            Endpoint::new(format!("{http_prefix}://{addr}")).context(CreateChannelSnafu)?;
        if force_http_scheme {
            let mut origin_parts = endpoint.uri().clone().into_parts();
            origin_parts.scheme = Some("https".parse().expect("valid https scheme"));
            let origin = match Uri::from_parts(origin_parts) {
                Ok(uri) => uri,
                Err(err) => {
                    return InvalidTlsConfigSnafu {
                        msg: format!("invalid tls origin uri, {err}"),
                    }
                    .fail()
                }
            };
            endpoint = endpoint.origin(origin);
        }

        if let Some(dur) = self.config().timeout {
            endpoint = endpoint.timeout(dur);
        }
        if let Some(dur) = self.config().connect_timeout {
            endpoint = endpoint.connect_timeout(dur);
        }
        if let Some(limit) = self.config().concurrency_limit {
            endpoint = endpoint.concurrency_limit(limit);
        }
        if let Some((limit, dur)) = self.config().rate_limit {
            endpoint = endpoint.rate_limit(limit, dur);
        }
        if let Some(size) = self.config().initial_stream_window_size {
            endpoint = endpoint.initial_stream_window_size(size);
        }
        if let Some(size) = self.config().initial_connection_window_size {
            endpoint = endpoint.initial_connection_window_size(size);
        }
        if let Some(dur) = self.config().http2_keep_alive_interval {
            endpoint = endpoint.http2_keep_alive_interval(dur);
        }
        if let Some(dur) = self.config().http2_keep_alive_timeout {
            endpoint = endpoint.keep_alive_timeout(dur);
        }
        if let Some(enabled) = self.config().http2_keep_alive_while_idle {
            endpoint = endpoint.keep_alive_while_idle(enabled);
        }
        if let Some(enabled) = self.config().http2_adaptive_window {
            endpoint = endpoint.http2_adaptive_window(enabled);
        }
        if apply_tonic_tls_config {
            if let Some(tls_config) = &self.inner.client_tls_config {
                endpoint = endpoint
                    .tls_config(tls_config.clone())
                    .context(CreateChannelSnafu)?;
            }
        }

        endpoint = endpoint
            .tcp_keepalive(self.config().tcp_keepalive)
            .tcp_nodelay(self.config().tcp_nodelay);

        Ok(endpoint)
    }

    fn trigger_channel_recycling(&self) {
        if self
            .inner
            .channel_recycle_started
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let pool = self.pool().clone();
        let cancel = self.inner.cancel.clone();
        let _handle = tokio::spawn(async move {
            recycle_channel_in_loop(pool, cancel, RECYCLE_CHANNEL_INTERVAL_SECS).await;
        });
    }
}

#[derive(Clone)]
struct HttpsOverHttpConnector {
    inner: hyper_rustls::HttpsConnector<HttpConnector>,
}

impl Service<Uri> for HttpsOverHttpConnector {
    type Response = <hyper_rustls::HttpsConnector<HttpConnector> as Service<Uri>>::Response;
    type Error = <hyper_rustls::HttpsConnector<HttpConnector> as Service<Uri>>::Error;
    type Future = <hyper_rustls::HttpsConnector<HttpConnector> as Service<Uri>>::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut parts = uri.into_parts();
        parts.scheme = Some("https".parse().expect("valid https scheme"));
        let https_uri = Uri::from_parts(parts).expect("valid uri parts");
        self.inner.call(https_uri)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientTlsOption {
    pub server_ca_cert_path: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    /// If non-empty, only allow these cipher suites.
    /// Names use IANA naming convention, e.g. "TLS_AES_256_GCM_SHA384".
    pub cipher_suites: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsVerify {
    #[default]
    VerifyPeer,
    VerifyNone,
}

/// gRPC compression algorithms supported by [`ChannelConfig`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrpcCompression {
    /// Gzip compression.
    Gzip,
    /// Zstandard compression.
    Zstd,
}

impl From<GrpcCompression> for CompressionEncoding {
    fn from(value: GrpcCompression) -> Self {
        match value {
            GrpcCompression::Gzip => CompressionEncoding::Gzip,
            GrpcCompression::Zstd => CompressionEncoding::Zstd,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelConfig {
    pub timeout: Option<Duration>,
    pub connect_timeout: Option<Duration>,
    pub concurrency_limit: Option<usize>,
    pub rate_limit: Option<(u64, Duration)>,
    pub initial_stream_window_size: Option<u32>,
    pub initial_connection_window_size: Option<u32>,
    pub http2_keep_alive_interval: Option<Duration>,
    pub http2_keep_alive_timeout: Option<Duration>,
    pub http2_keep_alive_while_idle: Option<bool>,
    pub http2_adaptive_window: Option<bool>,
    pub tcp_keepalive: Option<Duration>,
    pub tcp_nodelay: bool,
    pub tls_verify: TlsVerify,
    pub client_tls: Option<ClientTlsOption>,
    // Max gRPC receiving(decoding) message size
    pub max_recv_message_size: u64,
    // Max gRPC sending(encoding) message size
    pub max_send_message_size: u64,
    /// Preferred explicit gRPC compression encoding for requests.
    pub send_compression_encoding: Option<GrpcCompression>,
    /// Preferred explicit gRPC compression encoding for responses.
    pub accept_compression_encoding: Option<GrpcCompression>,
    /// Legacy compatibility flag that enables Zstd request compression.
    /// `send_compression_encoding` takes precedence when both are set.
    #[deprecated(
        note = "use with_send_compression(GrpcCompression) to choose the encoding explicitly"
    )]
    pub send_compression: bool,
    /// Legacy compatibility flag that enables Zstd response compression.
    /// `accept_compression_encoding` takes precedence when both are set.
    #[deprecated(
        note = "use with_accept_compression(GrpcCompression) to choose the encoding explicitly"
    )]
    pub accept_compression: bool,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        Self::default_with_legacy_grpc_compression()
    }
}

impl ChannelConfig {
    #[allow(deprecated)]
    fn default_with_legacy_grpc_compression() -> Self {
        Self {
            timeout: Some(Duration::from_secs(DEFAULT_GRPC_REQUEST_TIMEOUT_SECS)),
            connect_timeout: Some(Duration::from_secs(DEFAULT_GRPC_CONNECT_TIMEOUT_SECS)),
            concurrency_limit: None,
            rate_limit: None,
            initial_stream_window_size: None,
            initial_connection_window_size: None,
            http2_keep_alive_interval: Some(Duration::from_secs(30)),
            http2_keep_alive_timeout: None,
            http2_keep_alive_while_idle: Some(true),
            http2_adaptive_window: None,
            tcp_keepalive: None,
            tcp_nodelay: true,
            tls_verify: TlsVerify::VerifyPeer,
            client_tls: None,
            max_recv_message_size: DEFAULT_MAX_GRPC_RECV_MESSAGE_SIZE,
            max_send_message_size: DEFAULT_MAX_GRPC_SEND_MESSAGE_SIZE,
            send_compression_encoding: None,
            accept_compression_encoding: None,
            send_compression: false,
            accept_compression: false,
        }
    }

    pub fn new() -> Self {
        Default::default()
    }

    /// A timeout to each request.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// A timeout to connecting to the uri.
    ///
    /// Defaults to no timeout.
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// A concurrency limit to each request.
    pub fn concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limit = Some(limit);
        self
    }

    /// A rate limit to each request.
    pub fn rate_limit(mut self, limit: u64, duration: Duration) -> Self {
        self.rate_limit = Some((limit, duration));
        self
    }

    /// Sets the SETTINGS_INITIAL_WINDOW_SIZE option for HTTP2 stream-level flow control.
    /// Default is 65,535
    pub fn initial_stream_window_size(mut self, size: u32) -> Self {
        self.initial_stream_window_size = Some(size);
        self
    }

    /// Sets the max connection-level flow control for HTTP2
    ///
    /// Default is 65,535
    pub fn initial_connection_window_size(mut self, size: u32) -> Self {
        self.initial_connection_window_size = Some(size);
        self
    }

    /// Set http2 KEEP_ALIVE_INTERVAL. Uses hyper’s default otherwise.
    pub fn http2_keep_alive_interval(mut self, duration: Duration) -> Self {
        self.http2_keep_alive_interval = Some(duration);
        self
    }

    /// Set http2 KEEP_ALIVE_TIMEOUT. Uses hyper’s default otherwise.
    pub fn http2_keep_alive_timeout(mut self, duration: Duration) -> Self {
        self.http2_keep_alive_timeout = Some(duration);
        self
    }

    /// Set http2 KEEP_ALIVE_WHILE_IDLE. Uses hyper’s default otherwise.
    pub fn http2_keep_alive_while_idle(mut self, enabled: bool) -> Self {
        self.http2_keep_alive_while_idle = Some(enabled);
        self
    }

    /// Sets whether to use an adaptive flow control. Uses hyper’s default otherwise.
    pub fn http2_adaptive_window(mut self, enabled: bool) -> Self {
        self.http2_adaptive_window = Some(enabled);
        self
    }

    /// Set whether TCP keepalive messages are enabled on accepted connections.
    ///
    /// If None is specified, keepalive is disabled, otherwise the duration specified
    /// will be the time to remain idle before sending TCP keepalive probes.
    ///
    /// Default is no keepalive (None)
    pub fn tcp_keepalive(mut self, duration: Duration) -> Self {
        self.tcp_keepalive = Some(duration);
        self
    }

    /// Set the value of TCP_NODELAY option for accepted connections.
    ///
    /// Enabled by default.
    pub fn tcp_nodelay(mut self, enabled: bool) -> Self {
        self.tcp_nodelay = enabled;
        self
    }

    pub fn tls_verify(mut self, verify: TlsVerify) -> Self {
        self.tls_verify = verify;
        self
    }

    /// Set the value of tls client auth.
    ///
    /// Disabled by default.
    pub fn client_tls_config(mut self, client_tls_option: ClientTlsOption) -> Self {
        self.client_tls = Some(client_tls_option);
        self
    }

    /// Set the gRPC compression encoding used when sending requests.
    pub fn with_send_compression(mut self, compression: GrpcCompression) -> Self {
        self.send_compression_encoding = Some(compression);
        self
    }

    /// Set the gRPC compression encoding accepted from responses.
    pub fn with_accept_compression(mut self, compression: GrpcCompression) -> Self {
        self.accept_compression_encoding = Some(compression);
        self
    }

    #[allow(deprecated)]
    pub(crate) fn resolved_send_compression(&self) -> Option<GrpcCompression> {
        self.send_compression_encoding
            .or_else(|| self.send_compression.then_some(GrpcCompression::Zstd))
    }

    #[allow(deprecated)]
    pub(crate) fn resolved_accept_compression(&self) -> Option<GrpcCompression> {
        self.accept_compression_encoding
            .or_else(|| self.accept_compression.then_some(GrpcCompression::Zstd))
    }
}

#[derive(Debug)]
pub struct Channel {
    channel: InnerChannel,
    access: AtomicUsize,
    use_default_connector: bool,
}

impl Channel {
    #[inline]
    pub fn access(&self) -> usize {
        self.access.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn use_default_connector(&self) -> bool {
        self.use_default_connector
    }

    #[inline]
    pub fn increase_access(&self) {
        let _ = self.access.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Default)]
struct Pool {
    channels: DashMap<String, Channel>,
}

impl Pool {
    fn get(&self, addr: &str) -> Option<InnerChannel> {
        let channel = self.channels.get(addr);
        channel.map(|ch| {
            ch.increase_access();
            ch.channel.clone()
        })
    }

    fn entry(&self, addr: String) -> Entry<'_, String, Channel> {
        self.channels.entry(addr)
    }

    #[cfg(test)]
    fn get_access(&self, addr: &str) -> Option<usize> {
        let channel = self.channels.get(addr);
        channel.map(|ch| ch.access())
    }

    fn put(&self, addr: &str, channel: Channel) {
        let _ = self.channels.insert(addr.to_string(), channel);
    }

    fn retain_channel<F>(&self, f: F)
    where
        F: FnMut(&String, &mut Channel) -> bool,
    {
        self.channels.retain(f);
    }
}

async fn recycle_channel_in_loop(pool: Arc<Pool>, cancel: CancellationToken, interval_secs: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                break;
            },
            _ = interval.tick() => {}
        }

        pool.retain_channel(|_, c| c.access.swap(0, Ordering::Relaxed) != 0)
    }
}

fn ensure_default_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
}

fn parse_cipher_suite_name(name: &str) -> Option<rustls::CipherSuite> {
    match name {
        "TLS_AES_256_GCM_SHA384" => Some(rustls::CipherSuite::TLS13_AES_256_GCM_SHA384),
        "TLS_AES_128_GCM_SHA256" => Some(rustls::CipherSuite::TLS13_AES_128_GCM_SHA256),
        "TLS_CHACHA20_POLY1305_SHA256" => Some(rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => {
            Some(rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        }
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => {
            Some(rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
        }
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => {
            Some(rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        }
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => {
            Some(rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        }
        _ => None,
    }
}

fn make_custom_crypto_provider_with_ciphers(
    allowed_cipher_names: &[String],
) -> Result<Arc<rustls::crypto::CryptoProvider>> {
    let default = rustls::crypto::aws_lc_rs::default_provider();
    let allowed_suites: Vec<rustls::CipherSuite> = allowed_cipher_names
        .iter()
        .filter_map(|name| parse_cipher_suite_name(name))
        .collect();

    if allowed_suites.is_empty() {
        return InvalidTlsConfigSnafu {
            msg: format!("no valid cipher suite found in {:?}", allowed_cipher_names),
        }
        .fail();
    }

    let filtered: Vec<_> = default
        .cipher_suites
        .iter()
        .filter(|cs| allowed_suites.contains(&cs.suite()))
        .copied()
        .collect();

    if filtered.is_empty() {
        return InvalidTlsConfigSnafu {
            msg: format!(
                "none of the requested cipher suites are available: {:?}",
                allowed_cipher_names
            ),
        }
        .fail();
    }

    let custom = rustls::crypto::CryptoProvider {
        cipher_suites: filtered,
        kx_groups: default.kx_groups.clone(),
        signature_verification_algorithms: default.signature_verification_algorithms,
        secure_random: default.secure_random,
        key_provider: default.key_provider,
    };

    Ok(Arc::new(custom))
}

fn build_custom_client_tls_config(
    path_config: &ClientTlsOption,
    tls_verify: TlsVerify,
) -> Result<rustls::ClientConfig> {
    let provider: Arc<rustls::crypto::CryptoProvider> = if !path_config.cipher_suites.is_empty() {
        make_custom_crypto_provider_with_ciphers(&path_config.cipher_suites)?
    } else {
        rustls::crypto::aws_lc_rs::default_provider().into()
    };

    let has_client_cert = !path_config.client_cert_path.is_empty();
    let has_client_key = !path_config.client_key_path.is_empty();
    if has_client_cert != has_client_key {
        return InvalidTlsConfigSnafu {
            msg: "client cert and key must be configured together".to_string(),
        }
        .fail();
    }

    let builder = match rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
    {
        Ok(builder) => builder,
        Err(err) => {
            return InvalidTlsConfigSnafu {
                msg: format!("invalid TLS protocol versions, {err}"),
            }
            .fail()
        }
    };

    match tls_verify {
        TlsVerify::VerifyNone => {
            if has_client_cert {
                let cert_chain = load_client_cert_chain(path_config.client_cert_path.as_str())?;
                let private_key = load_client_private_key(path_config.client_key_path.as_str())?;
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                    .with_client_auth_cert(cert_chain, private_key)
                    .map_err(|err| {
                        InvalidTlsConfigSnafu {
                            msg: format!("invalid client certificate or key, {err}"),
                        }
                        .build()
                    })
            } else {
                Ok(builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                    .with_no_client_auth())
            }
        }
        TlsVerify::VerifyPeer => {
            let mut root_store = rustls::RootCertStore::empty();
            if !path_config.server_ca_cert_path.is_empty() {
                let ca_cert_pem = std::fs::read_to_string(&path_config.server_ca_cert_path)
                    .context(InvalidConfigFilePathSnafu)?;
                let mut reader = BufReader::new(ca_cert_pem.as_bytes());
                let certs = rustls_pemfile::certs(&mut reader)
                    .collect::<std::result::Result<Vec<_>, std::io::Error>>()
                    .map_err(|err| {
                        InvalidTlsConfigSnafu {
                            msg: format!(
                                "invalid CA cert file `{}`, {err}",
                                path_config.server_ca_cert_path
                            ),
                        }
                        .build()
                    })?;
                for cert in certs {
                    root_store.add(cert).map_err(|err| {
                        InvalidTlsConfigSnafu {
                            msg: format!("failed to add CA cert to root store, {err}"),
                        }
                        .build()
                    })?;
                }
            } else {
                // No explicit CA cert path: load system native root certificates
                let native_certs = rustls_native_certs::load_native_certs();
                for cert in native_certs.certs {
                    let _ = root_store.add(cert);
                }
                if root_store.is_empty() {
                    return InvalidTlsConfigSnafu {
                        msg: "no CA certificates found: ca_cert not configured and no system root certificates available".to_string(),
                    }
                    .fail();
                }
            }
            let config_builder = builder.with_root_certificates(root_store);
            if has_client_cert {
                let cert_chain = load_client_cert_chain(path_config.client_cert_path.as_str())?;
                let private_key = load_client_private_key(path_config.client_key_path.as_str())?;
                config_builder
                    .with_client_auth_cert(cert_chain, private_key)
                    .map_err(|err| {
                        InvalidTlsConfigSnafu {
                            msg: format!("invalid client certificate or key, {err}"),
                        }
                        .build()
                    })
            } else {
                Ok(config_builder.with_no_client_auth())
            }
        }
    }
}

fn load_client_cert_chain(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let cert_file = std::fs::File::open(path).context(InvalidConfigFilePathSnafu)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain = match rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, std::io::Error>>()
    {
        Ok(certs) => certs,
        Err(err) => {
            return InvalidTlsConfigSnafu {
                msg: format!("invalid client cert file `{path}`, {err}"),
            }
            .fail()
        }
    };
    if cert_chain.is_empty() {
        return InvalidTlsConfigSnafu {
            msg: format!("no client certificate found in `{path}`"),
        }
        .fail();
    }
    Ok(cert_chain)
}

fn load_client_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let key_file = std::fs::File::open(path).context(InvalidConfigFilePathSnafu)?;
    let mut key_reader = BufReader::new(key_file);
    match rustls_pemfile::private_key(&mut key_reader) {
        Ok(Some(key)) => Ok(key),
        Ok(None) => InvalidTlsConfigSnafu {
            msg: format!("no private key found in `{path}`"),
        }
        .fail(),
        Err(err) => InvalidTlsConfigSnafu {
            msg: format!("invalid client key file `{path}`, {err}"),
        }
        .fail(),
    }
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::aws_lc_rs::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use tower::service_fn;

    use super::*;

    #[should_panic]
    #[test]
    fn test_invalid_addr() {
        let mgr = ChannelManager::default();
        let addr = "http://test";

        let _ = mgr.get(addr).unwrap();
    }

    #[tokio::test]
    async fn test_access_count() {
        let mgr = ChannelManager::new();
        // Do not start recycle
        mgr.inner
            .channel_recycle_started
            .store(true, Ordering::Relaxed);
        let mgr = Arc::new(mgr);
        let addr = "test_uri";

        let mut joins = Vec::with_capacity(10);
        for _ in 0..10 {
            let mgr_clone = mgr.clone();
            let join = tokio::spawn(async move {
                for _ in 0..100 {
                    let _ = mgr_clone.get(addr);
                }
            });
            joins.push(join);
        }
        for join in joins {
            join.await.unwrap();
        }

        assert_eq!(1000, mgr.pool().get_access(addr).unwrap());

        mgr.pool()
            .retain_channel(|_, c| c.access.swap(0, Ordering::Relaxed) != 0);

        assert_eq!(0, mgr.pool().get_access(addr).unwrap());
    }

    #[test]
    #[allow(deprecated)]
    fn test_config() {
        let default_cfg = ChannelConfig::new();
        assert_eq!(
            ChannelConfig {
                timeout: Some(Duration::from_secs(DEFAULT_GRPC_REQUEST_TIMEOUT_SECS)),
                connect_timeout: Some(Duration::from_secs(DEFAULT_GRPC_CONNECT_TIMEOUT_SECS)),
                concurrency_limit: None,
                rate_limit: None,
                initial_stream_window_size: None,
                initial_connection_window_size: None,
                http2_keep_alive_interval: Some(Duration::from_secs(30)),
                http2_keep_alive_timeout: None,
                http2_keep_alive_while_idle: Some(true),
                http2_adaptive_window: None,
                tcp_keepalive: None,
                tcp_nodelay: true,
                tls_verify: TlsVerify::VerifyPeer,
                client_tls: None,
                max_recv_message_size: DEFAULT_MAX_GRPC_RECV_MESSAGE_SIZE,
                max_send_message_size: DEFAULT_MAX_GRPC_SEND_MESSAGE_SIZE,
                send_compression_encoding: None,
                accept_compression_encoding: None,
                send_compression: false,
                accept_compression: false,
            },
            default_cfg
        );

        let cfg = default_cfg
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_secs(5))
            .concurrency_limit(6)
            .rate_limit(5, Duration::from_secs(1))
            .initial_stream_window_size(10)
            .initial_connection_window_size(20)
            .http2_keep_alive_interval(Duration::from_secs(1))
            .http2_keep_alive_timeout(Duration::from_secs(3))
            .http2_keep_alive_while_idle(true)
            .http2_adaptive_window(true)
            .tcp_keepalive(Duration::from_secs(2))
            .tcp_nodelay(false)
            .tls_verify(TlsVerify::VerifyNone)
            .client_tls_config(ClientTlsOption {
                server_ca_cert_path: "some_server_path".to_string(),
                client_cert_path: "some_cert_path".to_string(),
                client_key_path: "some_key_path".to_string(),
                cipher_suites: vec![],
            });

        assert_eq!(
            ChannelConfig {
                timeout: Some(Duration::from_secs(3)),
                connect_timeout: Some(Duration::from_secs(5)),
                concurrency_limit: Some(6),
                rate_limit: Some((5, Duration::from_secs(1))),
                initial_stream_window_size: Some(10),
                initial_connection_window_size: Some(20),
                http2_keep_alive_interval: Some(Duration::from_secs(1)),
                http2_keep_alive_timeout: Some(Duration::from_secs(3)),
                http2_keep_alive_while_idle: Some(true),
                http2_adaptive_window: Some(true),
                tcp_keepalive: Some(Duration::from_secs(2)),
                tcp_nodelay: false,
                tls_verify: TlsVerify::VerifyNone,
                client_tls: Some(ClientTlsOption {
                    server_ca_cert_path: "some_server_path".to_string(),
                    client_cert_path: "some_cert_path".to_string(),
                    client_key_path: "some_key_path".to_string(),
                cipher_suites: vec![],
                }),
                max_recv_message_size: DEFAULT_MAX_GRPC_RECV_MESSAGE_SIZE,
                max_send_message_size: DEFAULT_MAX_GRPC_SEND_MESSAGE_SIZE,
                send_compression_encoding: None,
                accept_compression_encoding: None,
                send_compression: false,
                accept_compression: false,
            },
            cfg
        );
    }

    #[test]
    fn test_grpc_compression_config() {
        let config = ChannelConfig::new()
            .with_send_compression(GrpcCompression::Gzip)
            .with_accept_compression(GrpcCompression::Zstd);

        assert_eq!(
            Some(GrpcCompression::Gzip),
            config.send_compression_encoding
        );
        assert_eq!(
            Some(GrpcCompression::Zstd),
            config.accept_compression_encoding
        );
        #[allow(deprecated)]
        {
            assert!(!config.send_compression);
            assert!(!config.accept_compression);
        }
    }

    #[test]
    #[allow(deprecated)]
    fn test_explicit_grpc_compression_resolves_before_legacy_flags() {
        let config = ChannelConfig {
            send_compression_encoding: Some(GrpcCompression::Gzip),
            accept_compression_encoding: Some(GrpcCompression::Zstd),
            send_compression: true,
            accept_compression: false,
            ..ChannelConfig::default()
        };

        assert_eq!(
            Some(GrpcCompression::Gzip),
            config.resolved_send_compression()
        );
        assert_eq!(
            Some(GrpcCompression::Zstd),
            config.resolved_accept_compression()
        );
    }

    #[test]
    fn test_build_endpoint() {
        let config = ChannelConfig::new()
            .timeout(Duration::from_secs(3))
            .connect_timeout(Duration::from_secs(5))
            .concurrency_limit(6)
            .rate_limit(5, Duration::from_secs(1))
            .initial_stream_window_size(10)
            .initial_connection_window_size(20)
            .http2_keep_alive_interval(Duration::from_secs(1))
            .http2_keep_alive_timeout(Duration::from_secs(3))
            .http2_keep_alive_while_idle(true)
            .http2_adaptive_window(true)
            .tcp_keepalive(Duration::from_secs(2))
            .tcp_nodelay(true);
        let mgr = ChannelManager::with_config(config);

        let res = mgr.build_endpoint("test_addr", true, false);

        let _ = res.unwrap();
    }

    #[tokio::test]
    async fn test_channel_with_connector() {
        let mgr = ChannelManager::new();

        let addr = "test_addr";
        let res = mgr.get(addr);
        let _ = res.unwrap();

        mgr.retain_channel(|addr, channel| {
            assert_eq!("test_addr", addr);
            assert!(channel.use_default_connector());
            true
        });

        let (client, _) = tokio::io::duplex(1024);
        let mut client = Some(hyper_util::rt::TokioIo::new(client));
        let res = mgr.reset_with_connector(
            addr,
            service_fn(move |_| {
                let client = client.take().unwrap();
                async move { Ok::<_, std::io::Error>(client) }
            }),
        );

        let _ = res.unwrap();

        mgr.retain_channel(|addr, channel| {
            assert_eq!("test_addr", addr);
            assert!(!channel.use_default_connector());
            true
        });
    }

    #[tokio::test]
    async fn test_pool_release_with_channel_recycle() {
        let mgr = ChannelManager::new();

        let pool_holder = mgr.pool().clone();

        // start channel recycle task
        let addr = "test_addr";
        let _ = mgr.get(addr);

        let mgr_clone_1 = mgr.clone();
        let mgr_clone_2 = mgr.clone();
        assert_eq!(3, Arc::strong_count(mgr.pool()));

        drop(mgr_clone_1);
        drop(mgr_clone_2);
        assert_eq!(3, Arc::strong_count(mgr.pool()));

        drop(mgr);

        // wait for the channel recycle task to finish
        tokio::time::sleep(Duration::from_millis(10)).await;

        assert_eq!(1, Arc::strong_count(&pool_holder));
    }

    #[tokio::test]
    async fn test_pool_release_without_channel_recycle() {
        let mgr = ChannelManager::new();

        let pool_holder = mgr.pool().clone();

        let mgr_clone_1 = mgr.clone();
        let mgr_clone_2 = mgr.clone();
        assert_eq!(2, Arc::strong_count(mgr.pool()));

        drop(mgr_clone_1);
        drop(mgr_clone_2);
        assert_eq!(2, Arc::strong_count(mgr.pool()));

        drop(mgr);

        assert_eq!(1, Arc::strong_count(&pool_holder));
    }

    #[test]
    fn test_with_tls_config_allows_empty_cert_paths() {
        let config = ChannelConfig::new().client_tls_config(ClientTlsOption {
            server_ca_cert_path: String::new(),
            client_cert_path: String::new(),
            client_key_path: String::new(),
                cipher_suites: vec![],
        });

        let manager = ChannelManager::with_tls_config(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_with_tls_config_verify_none_ignores_missing_ca_file() {
        let config = ChannelConfig::new()
            .tls_verify(TlsVerify::VerifyNone)
            .client_tls_config(ClientTlsOption {
                server_ca_cert_path: "/tmp/nonexistent-ca.pem".to_string(),
                client_cert_path: String::new(),
                client_key_path: String::new(),
                cipher_suites: vec![],
            });

        let manager = ChannelManager::with_tls_config(config);
        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_get_uses_custom_connector_when_verify_none() {
        let config = ChannelConfig::new()
            .tls_verify(TlsVerify::VerifyNone)
            .client_tls_config(ClientTlsOption {
                server_ca_cert_path: String::new(),
                client_cert_path: String::new(),
                client_key_path: String::new(),
                cipher_suites: vec![],
            });

        let mgr = ChannelManager::with_tls_config(config).unwrap();
        let _ = mgr.get("test_addr").unwrap();

        mgr.retain_channel(|_, channel| {
            assert!(!channel.use_default_connector());
            true
        });
    }

    #[test]
    fn test_with_tls_config_rejects_partial_client_cert_config() {
        let config = ChannelConfig::new().client_tls_config(ClientTlsOption {
            server_ca_cert_path: String::new(),
            client_cert_path: "/tmp/client.crt".to_string(),
            client_key_path: String::new(),
                cipher_suites: vec![],
        });

        let manager = ChannelManager::with_tls_config(config);
        assert!(manager.is_err());
    }
}
