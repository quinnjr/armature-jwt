//! Integration tests for armature-jwt

use armature_jwt::*;
use jsonwebtoken::Algorithm;
use std::time::Duration;

#[test]
fn test_jwt_manager_creation() {
    let config = JwtConfig::new("test_secret_key_32_bytes_long!!!".to_string()).unwrap();
    let manager = JwtManager::new(config).unwrap();
    // JwtManager created successfully
    let _ = manager;
}

#[test]
fn test_jwt_config_builder() {
    let config = JwtConfig::new("test_secret_key_32_bytes_long!!!".to_string())
        .unwrap()
        .with_expiration(Duration::from_secs(7200))
        .with_issuer("my_app".to_string())
        .with_audience(vec!["api".to_string()])
        .with_leeway(60);

    assert_eq!(config.expires_in, Duration::from_secs(7200));
    assert_eq!(config.issuer, Some("my_app".to_string()));
    assert_eq!(config.audience, Some(vec!["api".to_string()]));
    assert_eq!(config.leeway, 60);
}

#[test]
fn test_jwt_config_with_algorithm() {
    let config = JwtConfig::new("test_secret_key_32_bytes_long!!!".to_string())
        .unwrap()
        .with_algorithm(Algorithm::HS256);
    assert_eq!(config.algorithm, Algorithm::HS256);

    let config = JwtConfig::new("test_secret_key_32_bytes_long!!!".to_string())
        .unwrap()
        .with_algorithm(Algorithm::HS384);
    assert_eq!(config.algorithm, Algorithm::HS384);

    let config = JwtConfig::new("test_secret_key_32_bytes_long!!!".to_string())
        .unwrap()
        .with_algorithm(Algorithm::HS512);
    assert_eq!(config.algorithm, Algorithm::HS512);
}

#[test]
fn test_jwt_config_default_values() {
    let config = JwtConfig::new("test_secret_key_32_bytes_long!!!".to_string()).unwrap();

    // Default algorithm should be HS256
    assert_eq!(config.algorithm, Algorithm::HS256);
}

// ---------------------------------------------------------------------------
// aws-lc-rs backend: every asymmetric family still signs and verifies.
// ---------------------------------------------------------------------------

const RSA_PRIV: &str = include_str!("fixtures/test_rsa_priv.pem");
const RSA_PUB: &str = include_str!("fixtures/test_rsa_pub.pem");
const EC_PRIV: &str = include_str!("fixtures/test_ec_priv.pem");
const EC_PUB: &str = include_str!("fixtures/test_ec_pub.pem");
const ED_PRIV: &str = include_str!("fixtures/test_ed25519_priv.pem");
const ED_PUB: &str = include_str!("fixtures/test_ed25519_pub.pem");

fn roundtrip(config: JwtConfig) {
    let manager = JwtManager::new(config).unwrap();
    let claims = StandardClaims::new()
        .with_subject("user".to_string())
        .with_expiration(3600);
    let token = manager.sign(&claims).unwrap();
    let decoded: StandardClaims = manager.verify(&token).unwrap();
    assert_eq!(decoded.sub.as_deref(), Some("user"));

    // A flipped signature byte must not verify.
    let mut tampered = token.clone();
    let last = tampered.pop().unwrap();
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(manager.verify::<StandardClaims>(&tampered).is_err());
}

#[test]
fn rsa_pkcs1_and_pss_roundtrip() {
    for alg in [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ] {
        roundtrip(JwtConfig::with_key_pair(
            RSA_PRIV.to_string(),
            RSA_PUB.to_string(),
            alg,
        ));
    }
}

#[test]
fn ecdsa_roundtrip() {
    roundtrip(JwtConfig::with_key_pair(
        EC_PRIV.to_string(),
        EC_PUB.to_string(),
        Algorithm::ES256,
    ));
}

#[test]
fn eddsa_roundtrip() {
    roundtrip(JwtConfig::with_key_pair(
        ED_PRIV.to_string(),
        ED_PUB.to_string(),
        Algorithm::EdDSA,
    ));
}

// ---------------------------------------------------------------------------
// Access vs refresh token separation (H4).
// ---------------------------------------------------------------------------

fn pair_manager() -> JwtManager {
    JwtManager::new(JwtConfig::new("test_secret_key_32_bytes_long!!!".to_string()).unwrap())
        .unwrap()
}

#[test]
fn verify_access_rejects_refresh_token() {
    let manager = pair_manager();
    let claims = serde_json::json!({ "sub": "u1", "roles": ["admin"] });
    let pair = manager.generate_token_pair(&claims).unwrap();

    let access: serde_json::Value = manager.verify_access(&pair.access_token).unwrap();
    assert_eq!(access["token_use"], "access");

    let refresh = manager.verify_access::<serde_json::Value>(&pair.refresh_token);
    assert!(
        matches!(refresh, Err(JwtError::InvalidToken(_))),
        "refresh token must not authenticate as an access token: {refresh:?}"
    );
}

#[test]
fn verify_access_rejects_unknown_token_use() {
    let manager = pair_manager();
    let exp = chrono::Utc::now().timestamp() + 3600;
    let token = manager
        .sign(&serde_json::json!({ "sub": "u1", "exp": exp, "token_use": "id" }))
        .unwrap();
    assert!(manager.verify_access::<serde_json::Value>(&token).is_err());
}

#[test]
fn verify_access_accepts_tokens_without_token_use() {
    let manager = pair_manager();
    let token = manager
        .sign(
            &StandardClaims::new()
                .with_subject("u1".to_string())
                .with_expiration(3600),
        )
        .unwrap();
    let claims: StandardClaims = manager.verify_access(&token).unwrap();
    assert_eq!(claims.sub.as_deref(), Some("u1"));
}

#[test]
fn refresh_requires_refresh_typ_header() {
    let manager = pair_manager();
    // A hand-signed token claiming token_use=refresh but lacking the refresh
    // `typ` header (e.g. an app that signs caller-influenced claims) must not
    // be accepted by the refresh path.
    let exp = chrono::Utc::now().timestamp() + 3600;
    let forged = manager
        .sign(&serde_json::json!({ "sub": "u1", "exp": exp, "token_use": "refresh" }))
        .unwrap();
    assert!(manager.refresh_token::<serde_json::Value>(&forged).is_err());

    let pair = manager
        .generate_token_pair(&serde_json::json!({ "sub": "u1" }))
        .unwrap();
    assert!(
        manager
            .refresh_token::<serde_json::Value>(&pair.refresh_token)
            .is_ok()
    );
    assert!(
        manager
            .refresh_token::<serde_json::Value>(&pair.access_token)
            .is_err()
    );
}

#[test]
fn token_types_redact_debug() {
    let manager = pair_manager();
    let pair = manager
        .generate_token_pair(&serde_json::json!({ "sub": "u1" }))
        .unwrap();
    let debug = format!("{pair:?}");
    assert!(!debug.contains(&pair.access_token), "{debug}");
    assert!(!debug.contains(&pair.refresh_token), "{debug}");
    assert!(debug.contains("<redacted>"));

    let token = Token::new(pair.access_token.clone(), 3600);
    let debug = format!("{token:?}");
    assert!(!debug.contains(&pair.access_token), "{debug}");
}
