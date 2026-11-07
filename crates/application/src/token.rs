//! Random bearer tokens: 256 random bits, encoded as 64 lowercase hex
//! characters. The database stores only SHA-256 of the raw bytes, so a
//! leaked metadata database does not yield usable sessions or invitations.
//!
//! Session tokens travel in an HttpOnly cookie. Invitation codes travel in
//! the fragment of an invitation link, which browsers do not send to the
//! server or in `Referer` headers.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

const TOKEN_BYTES: usize = 32;
const TOKEN_HEX_LEN: usize = TOKEN_BYTES * 2;

#[derive(Debug, thiserror::Error)]
#[error("the operating system random number generator failed")]
pub struct RandomnessError;

pub struct RandomToken {
    encoded: SecretString,
    hash: [u8; 32],
}

/// The value of a session cookie.
pub type SessionToken = RandomToken;

/// The secret part of an invitation link.
pub type InvitationToken = RandomToken;

impl RandomToken {
    pub fn generate() -> Result<Self, RandomnessError> {
        let mut bytes = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| RandomnessError)?;
        Ok(Self::from_bytes(&bytes))
    }

    /// Parses an encoded token. Anything other than exactly 64 lowercase hex
    /// characters is rejected before it reaches the database.
    pub fn parse(value: &str) -> Option<Self> {
        if value.len() != TOKEN_HEX_LEN {
            return None;
        }
        let mut bytes = [0u8; TOKEN_BYTES];
        for (byte, pair) in bytes.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
            *byte = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
        }
        Some(Self::from_bytes(&bytes))
    }

    fn from_bytes(bytes: &[u8; TOKEN_BYTES]) -> Self {
        let mut encoded = String::with_capacity(TOKEN_HEX_LEN);
        for byte in bytes {
            encoded.push(hex_digit(byte >> 4));
            encoded.push(hex_digit(byte & 0x0f));
        }
        Self {
            encoded: SecretString::from(encoded),
            hash: Sha256::digest(bytes).into(),
        }
    }

    /// The cookie value. Only the cookie writer should call this.
    pub fn expose_cookie_value(&self) -> &str {
        self.encoded.expose_secret()
    }

    /// The encoded token, for the one response that hands an invitation
    /// code to the operator who created it.
    pub fn expose_code(&self) -> &str {
        self.encoded.expose_secret()
    }

    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

impl fmt::Debug for RandomToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RandomToken([REDACTED])")
    }
}

const fn hex_digit(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'a' + nibble - 10) as char,
    }
}

const fn hex_value(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn generated_tokens_round_trip_and_differ() {
        let a = SessionToken::generate().unwrap();
        let b = SessionToken::generate().unwrap();
        assert_ne!(a.expose_cookie_value(), b.expose_cookie_value());
        let parsed = SessionToken::parse(a.expose_cookie_value()).unwrap();
        assert_eq!(parsed.hash(), a.hash());
        assert_eq!(a.expose_cookie_value().len(), 64);
    }

    #[test]
    fn malformed_values_are_rejected() {
        let good = "ab".repeat(32);
        assert!(SessionToken::parse(&good).is_some());
        assert!(SessionToken::parse(&good[..62]).is_none());
        assert!(SessionToken::parse(&"AB".repeat(32)).is_none());
        assert!(SessionToken::parse(&"zz".repeat(32)).is_none());
        assert!(SessionToken::parse(&format!("{good}00")).is_none());
        assert!(SessionToken::parse(&"é".repeat(32)).is_none());
    }

    #[test]
    fn hash_is_sha256_of_raw_bytes() {
        let token = SessionToken::parse(&"00".repeat(32)).unwrap();
        let expected: [u8; 32] = Sha256::digest([0u8; 32]).into();
        assert_eq!(token.hash(), &expected);
    }

    #[test]
    fn debug_output_is_redacted() {
        let token = SessionToken::generate().unwrap();
        let debug = format!("{token:?}");
        assert!(!debug.contains(token.expose_cookie_value()));
    }
}
