//! What a JWT-shaped API key says about itself.
//!
//! Self-hosted stacks sign their anon and service role keys with the
//! stack's JWT secret, which the dashboard does not hold. The claims read
//! here are therefore not verified: they are used to catch a key pasted
//! into the wrong field, refuse one that has already expired, and show when
//! a stored key expires. Whether the stack accepts a key is only known
//! from a check. Keys in the newer `sb_` format are not JWTs and have no
//! claims.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use supabase_dashboard_domain::connection::{ApiKeyError, CredentialKind};
use time::OffsetDateTime;

/// The claims the dashboard looks at.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyClaims {
    pub role: Option<String>,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Deserialize)]
struct RawClaims {
    role: Option<String>,
    exp: Option<serde_json::Number>,
}

/// The claims of a key shaped like a JWT, or `None` for any other key.
/// The key's length is already bounded by
/// [`supabase_dashboard_domain::connection::check_api_key`].
pub fn read_claims(key: &str) -> Option<KeyClaims> {
    let mut parts = key.split('.');
    let (Some(_header), Some(payload), Some(_signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    let bytes = URL_SAFE_NO_PAD.decode(payload.trim_end_matches('=')).ok()?;
    let raw: RawClaims = serde_json::from_slice(&bytes).ok()?;
    Some(KeyClaims {
        role: raw.role,
        expires_at: raw
            .exp
            .and_then(|exp| exp.as_i64())
            .and_then(|exp| OffsetDateTime::from_unix_timestamp(exp).ok()),
    })
}

/// Refuses a JWT key whose role belongs in the other field, or that has
/// expired by `now`. Other keys pass unchanged.
pub fn check_claims(
    kind: CredentialKind,
    key: &str,
    now: OffsetDateTime,
) -> Result<(), ApiKeyError> {
    let Some(claims) = read_claims(key) else {
        return Ok(());
    };
    match (kind, claims.role.as_deref()) {
        (CredentialKind::AnonKey, Some("service_role")) => {
            return Err(ApiKeyError::SecretInAnonSlot);
        }
        (CredentialKind::ServiceRoleKey, Some("anon")) => {
            return Err(ApiKeyError::PublishableInSecretSlot);
        }
        _ => {}
    }
    if claims.expires_at.is_some_and(|at| at <= now) {
        return Err(ApiKeyError::Expired);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(payload: &str) -> String {
        format!(
            "{}.{}.signature",
            URL_SAFE_NO_PAD.encode(r#"{"alg":"HS256","typ":"JWT"}"#),
            URL_SAFE_NO_PAD.encode(payload)
        )
    }

    #[test]
    fn claims_are_read_from_jwt_keys_only() {
        let key = jwt(r#"{"role":"anon","iss":"supabase","exp":1956528000}"#);
        assert_eq!(
            read_claims(&key),
            Some(KeyClaims {
                role: Some("anon".into()),
                expires_at: OffsetDateTime::from_unix_timestamp(1_956_528_000).ok(),
            })
        );
        assert_eq!(read_claims("sb_publishable_abc"), None);
        assert_eq!(read_claims("a.b"), None);
        assert_eq!(read_claims("a.b.c.d"), None);
        assert_eq!(read_claims("x.not base64!.y"), None);
        assert_eq!(read_claims(&jwt("[1,2]")), None);
        // A fractional or out-of-range expiry is treated as absent.
        assert_eq!(
            read_claims(&jwt(r#"{"exp":1.5}"#)).and_then(|c| c.expires_at),
            None
        );
        assert_eq!(
            read_claims(&jwt(r#"{"exp":99999999999999999}"#)).and_then(|c| c.expires_at),
            None
        );
    }

    #[test]
    fn keys_in_the_wrong_field_or_expired_are_refused() {
        let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).unwrap();
        let anon = jwt(r#"{"role":"anon","exp":1900000000}"#);
        let service = jwt(r#"{"role":"service_role","exp":1900000000}"#);
        let expired = jwt(r#"{"role":"anon","exp":1700000000}"#);
        assert_eq!(check_claims(CredentialKind::AnonKey, &anon, now), Ok(()));
        assert_eq!(
            check_claims(CredentialKind::ServiceRoleKey, &service, now),
            Ok(())
        );
        assert_eq!(
            check_claims(CredentialKind::AnonKey, &service, now),
            Err(ApiKeyError::SecretInAnonSlot)
        );
        assert_eq!(
            check_claims(CredentialKind::ServiceRoleKey, &anon, now),
            Err(ApiKeyError::PublishableInSecretSlot)
        );
        assert_eq!(
            check_claims(CredentialKind::AnonKey, &expired, now),
            Err(ApiKeyError::Expired)
        );
        assert_eq!(
            check_claims(CredentialKind::AnonKey, "sb_publishable_abc", now),
            Ok(())
        );
        assert_eq!(
            check_claims(CredentialKind::AnonKey, &jwt(r#"{"role":"anon"}"#), now),
            Ok(())
        );
    }
}
