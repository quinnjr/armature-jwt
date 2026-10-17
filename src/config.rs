// JWT configuration

use crate::{JwtError, Result};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;

/// Minimum length, in bytes, of an HMAC (`HS256`/`HS384`/`HS512`) secret.
///
/// RFC 7518 §3.2 requires a key at least as long as the hash output; 32 bytes
/// (256 bits) is the floor for `HS256` and is enforced for every HMAC
/// algorithm. Generate one with e.g. `openssl rand -base64 48`.
pub const MIN_HMAC_SECRET_LEN: usize = 32;

/// Normalized (lower-cased, alphanumerics only) fragments that mark a secret
/// as a placeholder copied from docs, templates or compose files rather than a
/// real random key. Any secret whose normalized form *contains* one of these is
/// rejected, regardless of its length.
const PLACEHOLDER_FRAGMENTS: &[&str] = &[
    "changeme",
    "changethis",
    "replaceme",
    "defaultsecret",
    "yoursecret",
    "placeholder",
    "notasecret",
];

/// Check that `secret` is acceptable as an HMAC signing/verification key.
///
/// Rejects empty secrets, secrets shorter than [`MIN_HMAC_SECRET_LEN`] bytes,
/// well-known placeholders (`"change-me-in-production"`,
/// `"default-secret-change-me"`, `"secret"`, `"CHANGE_ME_IN_PRODUCTION"`, …)
/// and trivially low-entropy values (fewer than 8 distinct bytes, e.g. a run
/// of one repeated character).
///
/// ```
/// use armature_jwt::config::validate_hmac_secret;
///
/// assert!(validate_hmac_secret("").is_err());
/// assert!(validate_hmac_secret("secret").is_err());
/// assert!(validate_hmac_secret("change-me-in-production-change-me-in-production").is_err());
/// assert!(validate_hmac_secret("Zq3v9Lw2Rk8Xp1Tn6Yb4Hc7Md0Fs5Gj2").is_ok());
/// ```
pub fn validate_hmac_secret(secret: &str) -> Result<()> {
    if secret.is_empty() {
        return Err(JwtError::ConfigError(
            "HMAC secret must not be empty".to_string(),
        ));
    }
    if secret.len() < MIN_HMAC_SECRET_LEN {
        return Err(JwtError::ConfigError(format!(
            "HMAC secret must be at least {MIN_HMAC_SECRET_LEN} bytes (got {})",
            secret.len()
        )));
    }
    let normalized: String = secret
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    if PLACEHOLDER_FRAGMENTS
        .iter()
        .any(|fragment| normalized.contains(fragment))
    {
        return Err(JwtError::ConfigError(
            "HMAC secret looks like a placeholder; generate a random secret \
             (e.g. `openssl rand -base64 48`)"
                .to_string(),
        ));
    }
    let mut seen = [false; 256];
    let distinct = secret
        .bytes()
        .filter(|&b| !std::mem::replace(&mut seen[b as usize], true))
        .count();
    if distinct < 8 {
        return Err(JwtError::ConfigError(
            "HMAC secret has too little entropy (fewer than 8 distinct bytes)".to_string(),
        ));
    }
    Ok(())
}

/// JWT configuration.
///
/// There is deliberately no `Default`: every configuration must carry real key
/// material. [`JwtConfig::new`] validates the HMAC secret (see
/// [`validate_hmac_secret`]), and [`JwtService::new`](crate::JwtService::new)
/// re-validates the whole config, so a secret assigned directly to the public
/// field or deserialized from a file is checked too.
///
/// The `secret` and `private_key` fields are redacted from `Debug` output and
/// never serialized (they are still *deserialized*, so a config can be loaded
/// from a file or the environment).
#[derive(Clone, Serialize, Deserialize)]
pub struct JwtConfig {
    /// Secret key for HS256/HS384/HS512 algorithms
    #[serde(default, skip_serializing)]
    pub secret: Option<String>,

    /// Public key for RS256/RS384/RS512/PS256/PS384/PS512/ES256/ES384/EdDSA
    /// algorithms (PEM format)
    pub public_key: Option<String>,

    /// Private key for RS256/RS384/RS512/PS256/PS384/PS512/ES256/ES384/EdDSA
    /// algorithms (PEM format)
    #[serde(default, skip_serializing)]
    pub private_key: Option<String>,

    /// Algorithm to use (default: HS256)
    pub algorithm: Algorithm,

    /// Token expiration time (default: 1 hour)
    pub expires_in: Duration,

    /// Refresh token expiration (default: 7 days)
    pub refresh_expires_in: Duration,

    /// Issuer (iss claim)
    pub issuer: Option<String>,

    /// Audience (aud claim)
    pub audience: Option<Vec<String>>,

    /// Validate expiration
    pub validate_exp: bool,

    /// Validate not before.
    ///
    /// **On by default** in both [`JwtConfig::new`] and [`JwtConfig::with_rsa`] — a token
    /// carrying a future `nbf` claim is rejected unless this is explicitly turned off via
    /// [`JwtConfig::with_nbf_validation`]`(false)`, for tokens that don't need not-before
    /// enforcement.
    pub validate_nbf: bool,

    /// Leeway for time validation (seconds)
    pub leeway: u64,
}

impl fmt::Debug for JwtConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redact = |opt: &Option<String>| opt.as_ref().map(|_| "<redacted>");
        f.debug_struct("JwtConfig")
            .field("secret", &redact(&self.secret))
            .field("public_key", &self.public_key)
            .field("private_key", &redact(&self.private_key))
            .field("algorithm", &self.algorithm)
            .field("expires_in", &self.expires_in)
            .field("refresh_expires_in", &self.refresh_expires_in)
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("validate_exp", &self.validate_exp)
            .field("validate_nbf", &self.validate_nbf)
            .field("leeway", &self.leeway)
            .finish()
    }
}

impl JwtConfig {
    /// Create an `HS256` configuration from an HMAC secret.
    ///
    /// # Errors
    ///
    /// Returns [`JwtError::ConfigError`] if the secret is empty, shorter than
    /// [`MIN_HMAC_SECRET_LEN`] bytes, a known placeholder, or trivially
    /// low-entropy (see [`validate_hmac_secret`]).
    ///
    /// ```
    /// use armature_jwt::JwtConfig;
    ///
    /// assert!(JwtConfig::new("change-me-in-production".to_string()).is_err());
    /// let config = JwtConfig::new("Zq3v9Lw2Rk8Xp1Tn6Yb4Hc7Md0Fs5Gj2".to_string()).unwrap();
    /// assert!(format!("{config:?}").contains("<redacted>"));
    /// ```
    pub fn new(secret: String) -> Result<Self> {
        validate_hmac_secret(&secret)?;
        Ok(Self {
            secret: Some(secret),
            public_key: None,
            private_key: None,
            algorithm: Algorithm::HS256,
            expires_in: Duration::from_secs(3600), // 1 hour
            refresh_expires_in: Duration::from_secs(604800), // 7 days
            issuer: None,
            audience: None,
            validate_exp: true,
            validate_nbf: true,
            leeway: 0,
        })
    }

    /// Create configuration with RSA keys
    pub fn with_rsa(private_key: String, public_key: String) -> Self {
        Self {
            secret: None,
            public_key: Some(public_key),
            private_key: Some(private_key),
            algorithm: Algorithm::RS256,
            expires_in: Duration::from_secs(3600),
            refresh_expires_in: Duration::from_secs(604800),
            issuer: None,
            audience: None,
            validate_exp: true,
            validate_nbf: true,
            leeway: 0,
        }
    }

    /// Create a configuration with an asymmetric key pair (PEM) for the given
    /// algorithm, e.g. `ES256` or `EdDSA`.
    ///
    /// Use [`JwtConfig::with_rsa`] for the RSA default (`RS256`).
    pub fn with_key_pair(private_key: String, public_key: String, algorithm: Algorithm) -> Self {
        Self {
            algorithm,
            ..Self::with_rsa(private_key, public_key)
        }
    }

    /// Check the configuration's key material for the selected algorithm.
    ///
    /// For HMAC algorithms the secret must be present and pass
    /// [`validate_hmac_secret`]. Called by [`JwtService::new`](crate::JwtService::new)
    /// and [`JwtService::verify_only`](crate::JwtService::verify_only), so a
    /// config whose public `secret` field was overwritten or deserialized
    /// cannot bypass the check.
    pub fn validate(&self) -> Result<()> {
        if Self::is_hmac(self.algorithm) {
            let secret = self.secret.as_deref().ok_or_else(|| {
                JwtError::ConfigError("Secret required for HMAC algorithms".to_string())
            })?;
            validate_hmac_secret(secret)?;
        }
        Ok(())
    }

    fn is_hmac(algorithm: Algorithm) -> bool {
        matches!(
            algorithm,
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512
        )
    }

    /// Set the algorithm
    pub fn with_algorithm(mut self, algorithm: Algorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Set expiration time
    pub fn with_expiration(mut self, duration: Duration) -> Self {
        self.expires_in = duration;
        self
    }

    /// Set refresh token expiration
    pub fn with_refresh_expiration(mut self, duration: Duration) -> Self {
        self.refresh_expires_in = duration;
        self
    }

    /// Set issuer
    pub fn with_issuer(mut self, issuer: String) -> Self {
        self.issuer = Some(issuer);
        self
    }

    /// Set audience
    pub fn with_audience(mut self, audience: Vec<String>) -> Self {
        self.audience = Some(audience);
        self
    }

    /// Set leeway
    pub fn with_leeway(mut self, leeway: u64) -> Self {
        self.leeway = leeway;
        self
    }

    /// Enable or disable `nbf` (not-before) validation.
    ///
    /// `validate_nbf` is `true` by default (see its doc comment), so a token with a future
    /// `nbf` claim is rejected unless this is called with `false` to opt out, for tokens that
    /// don't need not-before enforcement.
    pub fn with_nbf_validation(mut self, enabled: bool) -> Self {
        self.validate_nbf = enabled;
        self
    }

    /// Get encoding key
    pub fn encoding_key(&self) -> Result<EncodingKey> {
        match self.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let secret = self.secret.as_ref().ok_or_else(|| {
                    crate::JwtError::ConfigError("Secret required for HMAC algorithms".to_string())
                })?;
                Ok(EncodingKey::from_secret(secret.as_bytes()))
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                let private_key = self.private_key.as_ref().ok_or_else(|| {
                    crate::JwtError::ConfigError(
                        "Private key required for RSA algorithms".to_string(),
                    )
                })?;
                EncodingKey::from_rsa_pem(private_key.as_bytes())
                    .map_err(|e| crate::JwtError::ConfigError(e.to_string()))
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                let private_key = self.private_key.as_ref().ok_or_else(|| {
                    crate::JwtError::ConfigError(
                        "Private key required for ECDSA algorithms".to_string(),
                    )
                })?;
                EncodingKey::from_ec_pem(private_key.as_bytes())
                    .map_err(|e| crate::JwtError::ConfigError(e.to_string()))
            }
            Algorithm::EdDSA => {
                let private_key = self.private_key.as_ref().ok_or_else(|| {
                    crate::JwtError::ConfigError(
                        "Private key required for EdDSA algorithm".to_string(),
                    )
                })?;
                EncodingKey::from_ed_pem(private_key.as_bytes())
                    .map_err(|e| crate::JwtError::ConfigError(e.to_string()))
            }
            _ => Err(crate::JwtError::ConfigError(
                "Unsupported algorithm".to_string(),
            )),
        }
    }

    /// Get decoding key
    pub fn decoding_key(&self) -> Result<DecodingKey> {
        match self.algorithm {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
                let secret = self.secret.as_ref().ok_or_else(|| {
                    crate::JwtError::ConfigError("Secret required for HMAC algorithms".to_string())
                })?;
                Ok(DecodingKey::from_secret(secret.as_bytes()))
            }
            Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512 => {
                let public_key = self.public_key.as_ref().ok_or_else(|| {
                    crate::JwtError::ConfigError(
                        "Public key required for RSA algorithms".to_string(),
                    )
                })?;
                DecodingKey::from_rsa_pem(public_key.as_bytes())
                    .map_err(|e| crate::JwtError::ConfigError(e.to_string()))
            }
            Algorithm::ES256 | Algorithm::ES384 => {
                let public_key = self.public_key.as_ref().ok_or_else(|| {
                    crate::JwtError::ConfigError(
                        "Public key required for ECDSA algorithms".to_string(),
                    )
                })?;
                DecodingKey::from_ec_pem(public_key.as_bytes())
                    .map_err(|e| crate::JwtError::ConfigError(e.to_string()))
            }
            Algorithm::EdDSA => {
                let public_key = self.public_key.as_ref().ok_or_else(|| {
                    crate::JwtError::ConfigError(
                        "Public key required for EdDSA algorithm".to_string(),
                    )
                })?;
                DecodingKey::from_ed_pem(public_key.as_bytes())
                    .map_err(|e| crate::JwtError::ConfigError(e.to_string()))
            }
            _ => Err(crate::JwtError::ConfigError(
                "Unsupported algorithm".to_string(),
            )),
        }
    }

    /// Get validation config
    pub fn validation(&self) -> Validation {
        let mut validation = Validation::new(self.algorithm);
        validation.validate_exp = self.validate_exp;
        validation.validate_nbf = self.validate_nbf;
        validation.leeway = self.leeway;

        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
        }

        if let Some(ref aud) = self.audience {
            validation.set_audience(aud);
        }

        validation
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TEST_SECRET;

    #[test]
    fn test_new_config_defaults() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        assert!(config.secret.is_some());
        assert_eq!(config.algorithm, Algorithm::HS256);
        assert!(config.validate_exp);
    }

    #[test]
    fn rejects_empty_short_and_placeholder_secrets() {
        for weak in [
            "",
            "secret",
            "test-secret",
            "change-me-in-production",
            "CHANGE_ME_IN_PRODUCTION",
            "default-secret-change-me",
            "user-service-secret",
            // Long enough, but still a placeholder.
            "change-me-in-production-change-me-in-production",
            "please-replace-me-with-a-real-secret-value",
            "your-secret-key-goes-here-0123456789",
            // Long enough, but no entropy.
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "abababababababababababababababab",
        ] {
            assert!(
                JwtConfig::new(weak.to_string()).is_err(),
                "weak secret {weak:?} must be rejected"
            );
        }
        // 31 bytes of otherwise-random material is still too short.
        assert!(JwtConfig::new(TEST_SECRET[..31].to_string()).is_err());
        assert!(JwtConfig::new(TEST_SECRET[..32].to_string()).is_ok());
    }

    #[test]
    fn service_revalidates_secret_assigned_after_construction() {
        let mut config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        config.secret = Some("short".to_string());
        assert!(crate::JwtService::new(config.clone()).is_err());
        assert!(crate::JwtService::verify_only(config).is_err());
    }

    #[test]
    fn service_rejects_weak_secret_from_deserialized_config() {
        let mut value =
            serde_json::to_value(JwtConfig::new(TEST_SECRET.to_string()).unwrap()).unwrap();
        value["secret"] = serde_json::json!("change-me-in-production");
        let config: JwtConfig = serde_json::from_value(value).unwrap();
        assert!(crate::JwtService::new(config).is_err());
    }

    #[test]
    fn debug_redacts_secret_and_private_key() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains(TEST_SECRET), "secret leaked: {debug}");
        assert!(debug.contains("<redacted>"));

        let rsa = JwtConfig::with_rsa("PRIVATE-KEY-MATERIAL".to_string(), "PUB".to_string());
        let debug = format!("{rsa:?}");
        assert!(
            !debug.contains("PRIVATE-KEY-MATERIAL"),
            "key leaked: {debug}"
        );
        assert!(debug.contains("PUB"), "public key may be shown: {debug}");
    }

    #[test]
    fn serialize_skips_secret_and_private_key() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains(TEST_SECRET), "secret serialized: {json}");
        assert!(!json.contains("\"secret\""));

        let rsa = JwtConfig::with_rsa("PRIVATE-KEY-MATERIAL".to_string(), "PUB".to_string());
        let json = serde_json::to_string(&rsa).unwrap();
        assert!(
            !json.contains("PRIVATE-KEY-MATERIAL"),
            "key serialized: {json}"
        );
        assert!(!json.contains("private_key"));
    }

    #[test]
    fn test_config_builder() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_algorithm(Algorithm::HS512)
            .with_expiration(Duration::from_secs(7200))
            .with_issuer("my-app".to_string())
            .with_leeway(60);

        assert_eq!(config.algorithm, Algorithm::HS512);
        assert_eq!(config.expires_in, Duration::from_secs(7200));
        assert_eq!(config.issuer, Some("my-app".to_string()));
        assert_eq!(config.leeway, 60);
    }

    #[test]
    fn test_encoding_key() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        let key = config.encoding_key();
        assert!(key.is_ok());
    }

    #[test]
    fn test_decoding_key() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        let key = config.decoding_key();
        assert!(key.is_ok());
    }

    #[test]
    fn test_validation() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_issuer("my-issuer".to_string())
            .with_audience(vec!["my-audience".to_string()]);

        let validation = config.validation();
        assert!(validation.iss.is_some());
        assert!(validation.aud.is_some());
        assert!(validation.validate_exp);
    }

    #[test]
    fn test_algorithm_hs256() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_algorithm(Algorithm::HS256);
        assert_eq!(config.algorithm, Algorithm::HS256);
    }

    #[test]
    fn test_algorithm_hs384() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_algorithm(Algorithm::HS384);
        assert_eq!(config.algorithm, Algorithm::HS384);
    }

    #[test]
    fn test_algorithm_hs512() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_algorithm(Algorithm::HS512);
        assert_eq!(config.algorithm, Algorithm::HS512);
    }

    #[test]
    fn test_validation_enabled_by_default() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        assert!(config.validate_exp);

        let validation = config.validation();
        assert!(validation.validate_exp);
    }

    #[test]
    fn test_leeway_configuration() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_leeway(120);

        assert_eq!(config.leeway, 120);

        let validation = config.validation();
        assert_eq!(validation.leeway, 120);
    }

    #[test]
    fn test_audience_configuration() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_audience(vec!["app1".to_string()]);

        assert_eq!(config.audience, Some(vec!["app1".to_string()]));

        let validation = config.validation();
        assert!(validation.aud.is_some());
    }

    #[test]
    fn test_issuer_configuration() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_issuer("auth-server".to_string());

        assert_eq!(config.issuer, Some("auth-server".to_string()));

        let validation = config.validation();
        assert!(validation.iss.is_some());
    }

    #[test]
    fn test_expiration_duration() {
        let one_hour = Duration::from_secs(3600);
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_expiration(one_hour);

        assert_eq!(config.expires_in, one_hour);
    }

    #[test]
    fn test_default_expiration() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        assert_eq!(config.expires_in, Duration::from_secs(3600));
    }

    #[test]
    fn test_config_clone() {
        let config1 = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_issuer("issuer".to_string());

        let config2 = config1.clone();
        assert_eq!(config1.issuer, config2.issuer);
        assert_eq!(config1.algorithm, config2.algorithm);
    }

    #[test]
    fn test_config_with_all_options() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_algorithm(Algorithm::HS512)
            .with_expiration(Duration::from_secs(7200))
            .with_issuer("issuer".to_string())
            .with_audience(vec!["audience".to_string()])
            .with_leeway(60);

        assert_eq!(config.algorithm, Algorithm::HS512);
        assert_eq!(config.expires_in, Duration::from_secs(7200));
        assert_eq!(config.issuer, Some("issuer".to_string()));
        assert_eq!(config.audience, Some(vec!["audience".to_string()]));
        assert_eq!(config.leeway, 60);
        assert!(config.validate_exp);
    }

    #[test]
    fn test_validation_requirements() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_issuer("required-issuer".to_string())
            .with_audience(vec!["required-audience".to_string()]);

        let validation = config.validation();
        assert!(validation.iss.is_some());
        assert!(validation.aud.is_some());

        let expected_iss: std::collections::HashSet<String> =
            std::collections::HashSet::from(["required-issuer".to_string()]);
        assert_eq!(validation.iss.as_ref().unwrap(), &expected_iss);
    }

    #[test]
    fn test_zero_leeway() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_leeway(0);

        assert_eq!(config.leeway, 0);
    }

    #[test]
    fn test_long_expiration() {
        let one_year = Duration::from_secs(365 * 24 * 3600);
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_expiration(one_year);

        assert_eq!(config.expires_in, one_year);
    }

    #[test]
    fn test_nbf_validation_on_by_default() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        assert!(config.validate_nbf);

        let validation = config.validation();
        assert!(validation.validate_nbf);
    }

    #[test]
    fn test_with_nbf_validation_builder() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_nbf_validation(false);
        assert!(!config.validate_nbf);

        let validation = config.validation();
        assert!(!validation.validate_nbf);
    }

    /// A token with a future `nbf` is rejected when `validate_nbf` is left at its default (on)
    /// — this is the current, secure-by-default posture.
    #[test]
    fn future_nbf_token_rejected_by_default() {
        let config = JwtConfig::new(TEST_SECRET.to_string()).unwrap();
        assert!(config.validate_nbf);

        let service = crate::service::JwtService::new(config).unwrap();

        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "user-1",
            "nbf": now + 3600,
            "exp": now + 7200,
        });

        let token = service.sign(&claims).unwrap();
        let result: crate::Result<serde_json::Value> = service.verify(&token);
        assert!(
            result.is_err(),
            "future nbf should be rejected when validate_nbf is on (default): {result:?}"
        );
    }

    /// The same future-`nbf` token is accepted once `validate_nbf` is explicitly disabled via
    /// [`JwtConfig::with_nbf_validation`]`(false)`.
    #[test]
    fn future_nbf_token_accepted_when_validation_explicitly_disabled() {
        let config = JwtConfig::new(TEST_SECRET.to_string())
            .unwrap()
            .with_nbf_validation(false);
        assert!(!config.validate_nbf);

        let service = crate::service::JwtService::new(config).unwrap();

        let now = chrono::Utc::now().timestamp();
        let claims = serde_json::json!({
            "sub": "user-1",
            "nbf": now + 3600,
            "exp": now + 7200,
        });

        let token = service.sign(&claims).unwrap();
        let result: crate::Result<serde_json::Value> = service.verify(&token);
        assert!(
            result.is_ok(),
            "future nbf should be accepted when validate_nbf is explicitly disabled"
        );
    }
}
