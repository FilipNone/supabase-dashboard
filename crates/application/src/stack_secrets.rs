//! The secrets a new self-hosted Supabase stack starts with.
//!
//! Generated on the dashboard server from the operating system's random
//! number generator, in the formats upstream's
//! `docker/utils/generate-keys.sh` uses: hex for passwords, base64 for the
//! other secrets, and anon and service role keys signed with HS256 by the
//! stack's JWT secret, valid for five years. The byte counts give base64
//! values without padding, so no value contains `=`.
//!
//! Every value is a [`SecretString`], so it is redacted from `Debug`
//! output. Where the values go (the stack's deployment variables, and the
//! keys the dashboard needs, encrypted) is up to the caller.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, KeyInit, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;
use time::OffsetDateTime;

use crate::token::RandomnessError;

/// How long the generated anon and service role keys stay valid, as
/// upstream's script sets it: five years of 365 days.
pub const API_KEY_LIFETIME_SECONDS: i64 = 5 * 365 * 24 * 3600;

/// The issuer upstream's script puts in both keys.
const ISSUER: &str = "supabase";

/// The Studio user name. Upstream's default; the password is what keeps
/// Studio closed.
pub const STUDIO_USERNAME: &str = "supabase";

#[derive(Debug)]
pub struct StackSecrets {
    /// `POSTGRES_PASSWORD`: 16 random bytes as hex.
    pub postgres_password: SecretString,
    /// `JWT_SECRET`: 30 random bytes as base64, 40 characters.
    pub jwt_secret: SecretString,
    /// `ANON_KEY`, signed with `jwt_secret`.
    pub anon_key: SecretString,
    /// `SERVICE_ROLE_KEY`, signed with `jwt_secret`.
    pub service_role_key: SecretString,
    /// `SECRET_KEY_BASE` for Realtime: 48 random bytes as base64.
    pub secret_key_base: SecretString,
    /// `REALTIME_DB_ENC_KEY`: 8 random bytes as hex, the 16 characters
    /// Realtime's tenant table encryption expects.
    pub realtime_db_enc_key: SecretString,
    /// `PG_META_CRYPTO_KEY`: 24 random bytes as base64.
    pub pg_meta_crypto_key: SecretString,
    /// `DASHBOARD_PASSWORD`, the Studio password the gateway checks: 16
    /// random bytes as hex, so only letters and digits, as upstream asks.
    pub studio_password: SecretString,
    /// When the anon and service role keys were signed.
    pub keys_issued_at: OffsetDateTime,
}

impl StackSecrets {
    /// New secrets, with keys issued now.
    pub fn generate() -> Result<Self, RandomnessError> {
        Self::generate_at(OffsetDateTime::now_utc())
    }

    pub fn generate_at(issued_at: OffsetDateTime) -> Result<Self, RandomnessError> {
        let jwt_secret = SecretString::from(STANDARD.encode(random::<30>()?));
        let iat = issued_at.unix_timestamp();
        Ok(Self {
            postgres_password: SecretString::from(hex(&random::<16>()?)),
            anon_key: sign_api_key(&jwt_secret, ApiKeyRole::Anon, iat),
            service_role_key: sign_api_key(&jwt_secret, ApiKeyRole::ServiceRole, iat),
            jwt_secret,
            secret_key_base: SecretString::from(STANDARD.encode(random::<48>()?)),
            realtime_db_enc_key: SecretString::from(hex(&random::<8>()?)),
            pg_meta_crypto_key: SecretString::from(STANDARD.encode(random::<24>()?)),
            studio_password: SecretString::from(hex(&random::<16>()?)),
            keys_issued_at: issued_at,
        })
    }
}

/// The JSON field names, in the order [`StackSecrets::to_json`] writes
/// them.
const FIELDS: [&str; 8] = [
    "postgres_password",
    "jwt_secret",
    "anon_key",
    "service_role_key",
    "secret_key_base",
    "realtime_db_enc_key",
    "pg_meta_crypto_key",
    "studio_password",
];

impl StackSecrets {
    fn values(&self) -> [&SecretString; 8] {
        [
            &self.postgres_password,
            &self.jwt_secret,
            &self.anon_key,
            &self.service_role_key,
            &self.secret_key_base,
            &self.realtime_db_enc_key,
            &self.pg_meta_crypto_key,
            &self.studio_password,
        ]
    }

    /// The secrets as a JSON object, for sealing until they are stored
    /// where they belong.
    pub fn to_json(&self) -> SecretString {
        let mut object = serde_json::Map::new();
        for (name, value) in FIELDS.into_iter().zip(self.values()) {
            object.insert(name.to_owned(), value.expose_secret().into());
        }
        object.insert(
            "keys_issued_at".to_owned(),
            self.keys_issued_at.unix_timestamp().into(),
        );
        SecretString::from(serde_json::Value::Object(object).to_string())
    }

    /// Reads what [`Self::to_json`] wrote. `None` when a field is missing
    /// or of the wrong type.
    pub fn from_json(json: &SecretString) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(json.expose_secret()).ok()?;
        let field = |name: &str| {
            value
                .get(name)
                .and_then(serde_json::Value::as_str)
                .map(|s| SecretString::from(s.to_owned()))
        };
        Some(Self {
            postgres_password: field(FIELDS[0])?,
            jwt_secret: field(FIELDS[1])?,
            anon_key: field(FIELDS[2])?,
            service_role_key: field(FIELDS[3])?,
            secret_key_base: field(FIELDS[4])?,
            realtime_db_enc_key: field(FIELDS[5])?,
            pg_meta_crypto_key: field(FIELDS[6])?,
            studio_password: field(FIELDS[7])?,
            keys_issued_at: OffsetDateTime::from_unix_timestamp(
                value.get("keys_issued_at")?.as_i64()?,
            )
            .ok()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyRole {
    Anon,
    ServiceRole,
}

impl ApiKeyRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anon => "anon",
            Self::ServiceRole => "service_role",
        }
    }
}

/// An anon or service role key for `role`, signed with HS256 by
/// `jwt_secret` and valid for [`API_KEY_LIFETIME_SECONDS`] from `iat`.
pub fn sign_api_key(jwt_secret: &SecretString, role: ApiKeyRole, iat: i64) -> SecretString {
    let role = role.as_str();
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#);
    // In upstream's key order; `role` is a fixed name and needs no
    // escaping.
    let claims = format!(
        r#"{{"role":"{role}","iss":"{ISSUER}","iat":{iat},"exp":{}}}"#,
        iat.saturating_add(API_KEY_LIFETIME_SECONDS)
    );
    let claims = URL_SAFE_NO_PAD.encode(claims);
    let signed = format!("{header}.{claims}");
    // HMAC accepts a key of any length, so this cannot fail.
    let signature = match Hmac::<Sha256>::new_from_slice(jwt_secret.expose_secret().as_bytes()) {
        Ok(mut mac) => {
            mac.update(signed.as_bytes());
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        }
        Err(_) => String::new(),
    };
    SecretString::from(format!("{signed}.{signature}"))
}

fn random<const N: usize>() -> Result<[u8; N], RandomnessError> {
    let mut bytes = [0u8; N];
    getrandom::fill(&mut bytes).map_err(|_| RandomnessError)?;
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            // Writing to a String does not fail.
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key_claims::read_claims;

    /// Computed with Python's `hmac` and `base64` modules, independently of
    /// this code, for the secret below and `iat` 2026-01-01T00:00:00Z.
    const VECTOR_ANON: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoiYW5vbiIsImlzcyI6InN1cGFiYXNlIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjE5MjQ5MDU2MDB9.7Eq5aiasYMm8bCU_671hAmdV_osXfdcXwIbf13PIyug";
    const VECTOR_SERVICE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3NjcyMjU2MDAsImV4cCI6MTkyNDkwNTYwMH0.N-8g1lkcao6ArWQPAP2puadSzTTk1I4OFjhhOh0-AWo";

    #[test]
    fn keys_match_an_independently_signed_vector() {
        let secret = SecretString::from("synthetic-test-jwt-secret-for-a-vector");
        let iat = 1_767_225_600;
        assert_eq!(
            sign_api_key(&secret, ApiKeyRole::Anon, iat).expose_secret(),
            VECTOR_ANON
        );
        assert_eq!(
            sign_api_key(&secret, ApiKeyRole::ServiceRole, iat).expose_secret(),
            VECTOR_SERVICE
        );
    }

    #[test]
    fn generated_secrets_have_upstreams_formats() {
        let issued = OffsetDateTime::from_unix_timestamp(1_767_225_600).unwrap();
        let secrets = StackSecrets::generate_at(issued).unwrap();
        let is_hex = |s: &SecretString, len: usize| {
            let s = s.expose_secret();
            s.len() == len
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        assert!(is_hex(&secrets.postgres_password, 32));
        assert!(is_hex(&secrets.studio_password, 32));
        assert!(is_hex(&secrets.realtime_db_enc_key, 16));
        for (value, len) in [
            (&secrets.jwt_secret, 40),
            (&secrets.secret_key_base, 64),
            (&secrets.pg_meta_crypto_key, 32),
        ] {
            let value = value.expose_secret();
            assert_eq!(value.len(), len);
            assert!(!value.contains('='));
            assert_eq!(STANDARD.decode(value).unwrap().len(), len / 4 * 3);
        }

        let expires = issued + time::Duration::seconds(API_KEY_LIFETIME_SECONDS);
        for (key, role) in [
            (&secrets.anon_key, ApiKeyRole::Anon),
            (&secrets.service_role_key, ApiKeyRole::ServiceRole),
        ] {
            let claims = read_claims(key.expose_secret()).unwrap();
            assert_eq!(claims.role.as_deref(), Some(role.as_str()));
            assert_eq!(claims.expires_at, Some(expires));
            // The key verifies under the generated secret.
            let resigned = sign_api_key(&secrets.jwt_secret, role, issued.unix_timestamp());
            assert_eq!(resigned.expose_secret(), key.expose_secret());
        }
    }

    #[test]
    fn secrets_survive_their_json_form() {
        let secrets = StackSecrets::generate().unwrap();
        let back = StackSecrets::from_json(&secrets.to_json()).unwrap();
        for (a, b) in secrets.values().into_iter().zip(back.values()) {
            assert_eq!(a.expose_secret(), b.expose_secret());
        }
        assert_eq!(
            back.keys_issued_at.unix_timestamp(),
            secrets.keys_issued_at.unix_timestamp()
        );
        assert!(StackSecrets::from_json(&SecretString::from(r#"{"jwt_secret":"x"}"#)).is_none());
    }

    #[test]
    fn two_stacks_never_share_secrets() {
        let a = StackSecrets::generate().unwrap();
        let b = StackSecrets::generate().unwrap();
        assert_ne!(a.jwt_secret.expose_secret(), b.jwt_secret.expose_secret());
        assert_ne!(
            a.postgres_password.expose_secret(),
            b.postgres_password.expose_secret()
        );
        assert_ne!(
            a.studio_password.expose_secret(),
            b.studio_password.expose_secret()
        );
    }

    #[test]
    fn debug_output_shows_no_secret() {
        let secrets = StackSecrets::generate().unwrap();
        let debug = format!("{secrets:?}");
        for value in [
            &secrets.postgres_password,
            &secrets.jwt_secret,
            &secrets.anon_key,
            &secrets.studio_password,
        ] {
            assert!(!debug.contains(value.expose_secret()));
        }
    }
}
