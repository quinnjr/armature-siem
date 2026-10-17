//! SIEM configuration with builder pattern

use crate::error::SiemError;
use std::time::Duration;

/// SIEM provider type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiemProvider {
    /// Splunk Enterprise / Cloud
    Splunk,
    /// Elasticsearch / Elastic Security
    Elastic,
    /// IBM QRadar
    QRadar,
    /// Microsoft Sentinel
    Sentinel,
    /// Sumo Logic
    SumoLogic,
    /// Datadog Security
    Datadog,
    /// LogRhythm
    LogRhythm,
    /// ArcSight (Micro Focus)
    ArcSight,
    /// Generic Syslog
    Syslog,
    /// Custom/Generic HTTPS endpoint
    Custom,
}

impl std::fmt::Display for SiemProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SiemProvider::Splunk => write!(f, "Splunk"),
            SiemProvider::Elastic => write!(f, "Elastic"),
            SiemProvider::QRadar => write!(f, "QRadar"),
            SiemProvider::Sentinel => write!(f, "Sentinel"),
            SiemProvider::SumoLogic => write!(f, "SumoLogic"),
            SiemProvider::Datadog => write!(f, "Datadog"),
            SiemProvider::LogRhythm => write!(f, "LogRhythm"),
            SiemProvider::ArcSight => write!(f, "ArcSight"),
            SiemProvider::Syslog => write!(f, "Syslog"),
            SiemProvider::Custom => write!(f, "Custom"),
        }
    }
}

/// Event format for SIEM systems
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EventFormat {
    /// JSON format (most flexible)
    #[default]
    Json,
    /// Common Event Format (ArcSight, Splunk, etc.)
    Cef,
    /// Log Event Extended Format (IBM QRadar)
    Leef,
    /// Syslog RFC 5424
    Syslog,
    /// Elastic Common Schema
    Ecs,
}

impl std::fmt::Display for EventFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventFormat::Json => write!(f, "JSON"),
            EventFormat::Cef => write!(f, "CEF"),
            EventFormat::Leef => write!(f, "LEEF"),
            EventFormat::Syslog => write!(f, "Syslog"),
            EventFormat::Ecs => write!(f, "ECS"),
        }
    }
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Transport {
    /// HTTPS (HTTP Event Collector, etc.)
    #[default]
    Https,
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// TLS over TCP
    Tls,
}

/// Syslog facility
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum SyslogFacility {
    Kern = 0,
    User = 1,
    Mail = 2,
    Daemon = 3,
    Auth = 4,
    Syslog = 5,
    Lpr = 6,
    News = 7,
    Uucp = 8,
    Cron = 9,
    Authpriv = 10,
    Ftp = 11,
    #[default]
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

/// SIEM client configuration
///
/// `Debug` is implemented by hand so the authentication `token` and basic-auth
/// `password` are printed as `[REDACTED]`: a configuration dumped into a log
/// line must not carry the credential to the log store.
#[derive(Clone)]
#[non_exhaustive]
pub struct SiemConfig {
    /// Target SIEM provider
    pub provider: SiemProvider,
    /// Endpoint URL or host:port
    pub endpoint: String,
    /// Event format
    pub format: EventFormat,
    /// Transport protocol
    pub transport: Transport,
    /// Authentication token (HEC token, API key, etc.)
    pub token: Option<String>,
    /// Azure Log Analytics workspace ID (Sentinel `SharedKey` authentication)
    pub workspace_id: Option<String>,
    /// Username for basic auth
    pub username: Option<String>,
    /// Password for basic auth
    pub password: Option<String>,
    /// Index/source for events (Splunk index, Elastic index, etc.)
    pub index: Option<String>,
    /// Source type (for Splunk)
    pub source_type: Option<String>,
    /// Source (for Splunk/CEF)
    pub source: Option<String>,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Enable batching
    pub batching_enabled: bool,
    /// Batch size (number of events)
    pub batch_size: usize,
    /// Batch flush interval
    pub batch_flush_interval: Duration,
    /// Verify the server's TLS certificate (default `true`).
    ///
    /// `false` is only honored when the crate is built with the
    /// `dangerous-insecure-tls` feature. Without it, [`SiemConfig::validate`]
    /// and every transport constructor reject the configuration, so a
    /// verification switch flipped by mistake fails closed instead of sending
    /// security events to whoever answers on the endpoint.
    pub tls_verify: bool,
    /// Custom CA certificate path
    pub ca_cert_path: Option<String>,
    /// Syslog facility (for Syslog format)
    pub syslog_facility: SyslogFacility,
    /// Application name (for Syslog/CEF)
    pub app_name: String,
    /// CEF vendor name
    pub cef_vendor: String,
    /// CEF product name
    pub cef_product: String,
    /// CEF product version
    pub cef_version: String,
    /// Enable compression (gzip)
    pub compression: bool,
    /// Max retries on failure
    pub max_retries: u32,
    /// Retry delay
    pub retry_delay: Duration,
}

impl Default for SiemConfig {
    fn default() -> Self {
        Self {
            provider: SiemProvider::Splunk,
            endpoint: String::new(),
            format: EventFormat::Json,
            transport: Transport::Https,
            token: None,
            workspace_id: None,
            username: None,
            password: None,
            index: None,
            source_type: None,
            source: None,
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(30),
            batching_enabled: true,
            batch_size: 100,
            batch_flush_interval: Duration::from_secs(5),
            tls_verify: true,
            ca_cert_path: None,
            syslog_facility: SyslogFacility::default(),
            app_name: "armature".to_string(),
            cef_vendor: "Armature".to_string(),
            cef_product: "ArmatureFramework".to_string(),
            cef_version: "1.0".to_string(),
            compression: false,
            max_retries: 3,
            retry_delay: Duration::from_millis(1000),
        }
    }
}

const REDACTED: &str = "[REDACTED]";

impl std::fmt::Debug for SiemConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiemConfig")
            .field("provider", &self.provider)
            .field("endpoint", &self.endpoint)
            .field("format", &self.format)
            .field("transport", &self.transport)
            .field("token", &self.token.as_ref().map(|_| REDACTED))
            .field("workspace_id", &self.workspace_id)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| REDACTED))
            .field("index", &self.index)
            .field("source_type", &self.source_type)
            .field("source", &self.source)
            .field("connect_timeout", &self.connect_timeout)
            .field("request_timeout", &self.request_timeout)
            .field("batching_enabled", &self.batching_enabled)
            .field("batch_size", &self.batch_size)
            .field("batch_flush_interval", &self.batch_flush_interval)
            .field("tls_verify", &self.tls_verify)
            .field("ca_cert_path", &self.ca_cert_path)
            .field("syslog_facility", &self.syslog_facility)
            .field("app_name", &self.app_name)
            .field("cef_vendor", &self.cef_vendor)
            .field("cef_product", &self.cef_product)
            .field("cef_version", &self.cef_version)
            .field("compression", &self.compression)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .finish()
    }
}

/// Gate for a configuration that disables TLS certificate verification.
///
/// With the `dangerous-insecure-tls` feature this logs a warning and allows
/// it; without the feature it is a configuration error. Every place that
/// would act on `tls_verify == false` calls this first, so the field cannot
/// be flipped after [`SiemConfig::validate`] to sneak past the check.
pub(crate) fn insecure_tls_allowed(endpoint: &str) -> Result<(), SiemError> {
    #[cfg(feature = "dangerous-insecure-tls")]
    {
        tracing::warn!(
            endpoint = %endpoint,
            "SIEM TLS certificate verification is DISABLED: events can be read or altered by anyone able to intercept the connection"
        );
        Ok(())
    }
    #[cfg(not(feature = "dangerous-insecure-tls"))]
    {
        let _ = endpoint;
        Err(SiemError::Config(
            "tls_verify = false requires the `dangerous-insecure-tls` feature of armature-siem; \
             trust a private collector with `ca_cert` instead"
                .to_string(),
        ))
    }
}

impl SiemConfig {
    /// Create a new config builder
    pub fn builder() -> SiemConfigBuilder {
        SiemConfigBuilder::default()
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), SiemError> {
        if self.endpoint.is_empty() {
            return Err(SiemError::Config("Endpoint is required".to_string()));
        }

        if !self.tls_verify {
            insecure_tls_allowed(&self.endpoint)?;
        }

        // Validate transport/endpoint combinations
        match self.transport {
            Transport::Https => {
                if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
                    return Err(SiemError::Config(
                        "HTTPS transport requires http:// or https:// endpoint".to_string(),
                    ));
                }
            }
            Transport::Tcp | Transport::Udp | Transport::Tls => {
                // Should be host:port format
                if !self.endpoint.contains(':') {
                    return Err(SiemError::Config(
                        "TCP/UDP transport requires host:port format".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }
}

/// Builder for SIEM configuration
#[derive(Default)]
pub struct SiemConfigBuilder {
    config: SiemConfig,
}

impl SiemConfigBuilder {
    /// Set the SIEM provider
    pub fn provider(mut self, provider: SiemProvider) -> Self {
        self.config.provider = provider;
        // Set sensible defaults based on provider
        match provider {
            SiemProvider::Splunk => {
                self.config.format = EventFormat::Json;
                self.config.transport = Transport::Https;
            }
            SiemProvider::Elastic => {
                self.config.format = EventFormat::Ecs;
                self.config.transport = Transport::Https;
            }
            SiemProvider::QRadar => {
                self.config.format = EventFormat::Leef;
                self.config.transport = Transport::Tcp;
            }
            SiemProvider::Sentinel => {
                self.config.format = EventFormat::Json;
                self.config.transport = Transport::Https;
            }
            SiemProvider::ArcSight => {
                self.config.format = EventFormat::Cef;
                self.config.transport = Transport::Tcp;
            }
            SiemProvider::Syslog => {
                self.config.format = EventFormat::Syslog;
                self.config.transport = Transport::Udp;
            }
            _ => {}
        }
        self
    }

    /// Set the endpoint URL or host:port
    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.config.endpoint = endpoint.into();
        self
    }

    /// Set the event format
    pub fn format(mut self, format: EventFormat) -> Self {
        self.config.format = format;
        self
    }

    /// Set the transport protocol
    pub fn transport(mut self, transport: Transport) -> Self {
        self.config.transport = transport;
        self
    }

    /// Set the authentication token
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.config.token = Some(token.into());
        self
    }

    /// Set the Azure Log Analytics workspace ID (Sentinel `SharedKey` auth)
    pub fn workspace_id(mut self, workspace_id: impl Into<String>) -> Self {
        self.config.workspace_id = Some(workspace_id.into());
        self
    }

    /// Set basic auth credentials
    pub fn basic_auth(mut self, username: impl Into<String>, password: impl Into<String>) -> Self {
        self.config.username = Some(username.into());
        self.config.password = Some(password.into());
        self
    }

    /// Set the index/source
    pub fn index(mut self, index: impl Into<String>) -> Self {
        self.config.index = Some(index.into());
        self
    }

    /// Set the source type (Splunk)
    pub fn source_type(mut self, source_type: impl Into<String>) -> Self {
        self.config.source_type = Some(source_type.into());
        self
    }

    /// Set the source (Splunk/CEF)
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.config.source = Some(source.into());
        self
    }

    /// Set connection timeout
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set request timeout
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    /// Enable/disable batching
    pub fn batching(mut self, enabled: bool) -> Self {
        self.config.batching_enabled = enabled;
        self
    }

    /// Set batch size
    pub fn batch_size(mut self, size: usize) -> Self {
        self.config.batch_size = size;
        self
    }

    /// Set batch flush interval
    pub fn batch_flush_interval(mut self, interval: Duration) -> Self {
        self.config.batch_flush_interval = interval;
        self
    }

    /// Disable TLS certificate verification.
    ///
    /// Only exists with the `dangerous-insecure-tls` feature, and logs a
    /// warning whenever a transport is built from the resulting config. For a
    /// self-signed or private collector, prefer [`SiemConfigBuilder::ca_cert`],
    /// which keeps verification on against your own CA.
    #[cfg(feature = "dangerous-insecure-tls")]
    pub fn danger_accept_invalid_certs(mut self) -> Self {
        self.config.tls_verify = false;
        self
    }

    /// Set custom CA certificate path
    pub fn ca_cert(mut self, path: impl Into<String>) -> Self {
        self.config.ca_cert_path = Some(path.into());
        self
    }

    /// Set syslog facility
    pub fn syslog_facility(mut self, facility: SyslogFacility) -> Self {
        self.config.syslog_facility = facility;
        self
    }

    /// Set application name
    pub fn app_name(mut self, name: impl Into<String>) -> Self {
        self.config.app_name = name.into();
        self
    }

    /// Set CEF vendor
    pub fn cef_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.config.cef_vendor = vendor.into();
        self
    }

    /// Set CEF product
    pub fn cef_product(mut self, product: impl Into<String>) -> Self {
        self.config.cef_product = product.into();
        self
    }

    /// Set CEF version
    pub fn cef_version(mut self, version: impl Into<String>) -> Self {
        self.config.cef_version = version.into();
        self
    }

    /// Enable/disable compression
    pub fn compression(mut self, enabled: bool) -> Self {
        self.config.compression = enabled;
        self
    }

    /// Set max retries
    pub fn max_retries(mut self, retries: u32) -> Self {
        self.config.max_retries = retries;
        self
    }

    /// Set retry delay
    pub fn retry_delay(mut self, delay: Duration) -> Self {
        self.config.retry_delay = delay;
        self
    }

    /// Build the configuration
    pub fn build(self) -> Result<SiemConfig, SiemError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_builder() {
        let config = SiemConfig::builder()
            .provider(SiemProvider::Splunk)
            .endpoint("https://splunk.example.com:8088")
            .token("my-hec-token")
            .index("security")
            .build()
            .unwrap();

        assert_eq!(config.provider, SiemProvider::Splunk);
        assert_eq!(config.endpoint, "https://splunk.example.com:8088");
        assert_eq!(config.token, Some("my-hec-token".to_string()));
        assert_eq!(config.index, Some("security".to_string()));
    }

    #[test]
    fn test_config_validation_empty_endpoint() {
        let result = SiemConfig::builder().provider(SiemProvider::Splunk).build();

        assert!(result.is_err());
    }

    #[test]
    fn test_provider_defaults() {
        let config = SiemConfig::builder()
            .provider(SiemProvider::QRadar)
            .endpoint("qradar.example.com:514")
            .build()
            .unwrap();

        assert_eq!(config.format, EventFormat::Leef);
        assert_eq!(config.transport, Transport::Tcp);
    }

    #[test]
    fn debug_redacts_token_and_password() {
        let config = SiemConfig::builder()
            .provider(SiemProvider::Splunk)
            .endpoint("https://splunk.example.com:8088")
            .token("hec-token-super-secret")
            .basic_auth("svc-user", "basic-password-super-secret")
            .build()
            .unwrap();

        let debug = format!("{:?}", config);
        assert!(!debug.contains("hec-token-super-secret"), "{debug}");
        assert!(!debug.contains("basic-password-super-secret"), "{debug}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        // Non-secret fields stay visible for troubleshooting.
        assert!(debug.contains("svc-user"), "{debug}");
        assert!(debug.contains("splunk.example.com"), "{debug}");
    }

    #[test]
    fn tls_verify_defaults_on() {
        assert!(SiemConfig::default().tls_verify);
    }

    /// Without `dangerous-insecure-tls`, a config with verification off is
    /// rejected at validation time even when the public field is set directly.
    #[cfg(not(feature = "dangerous-insecure-tls"))]
    #[test]
    fn disabling_tls_verification_fails_closed_without_feature() {
        let mut config = SiemConfig::builder()
            .provider(SiemProvider::Syslog)
            .transport(Transport::Tls)
            .endpoint("collector.example.com:6514")
            .build()
            .unwrap();
        config.tls_verify = false;

        match config.validate() {
            Err(SiemError::Config(msg)) => {
                assert!(msg.contains("dangerous-insecure-tls"), "{msg}")
            }
            other => panic!("expected config error, got {other:?}"),
        }
    }

    #[cfg(feature = "dangerous-insecure-tls")]
    #[test]
    fn disabling_tls_verification_allowed_with_feature() {
        let config = SiemConfig::builder()
            .provider(SiemProvider::Syslog)
            .transport(Transport::Tls)
            .endpoint("collector.example.com:6514")
            .danger_accept_invalid_certs()
            .build()
            .unwrap();
        assert!(!config.tls_verify);
    }
}
