//! Tox-style contact identity.
//!
//! Layout (36 bytes -> 72 uppercase hex characters):
//!
//!   [ 0..32 ]  public key   (Curve25519, from the Olm account)
//!   [32..34 ]  nospam       (rotatable spam shield)
//!   [34..36 ]  checksum     (XOR of even bytes, XOR of odd bytes)
//!
//! Tox itself uses a 4-byte nospam for a 76-char ID. This uses 2 bytes to hit
//! exactly 72 characters. Cost: 65,536 possible nospam values instead of ~4.3
//! billion, so a determined attacker could brute-force valid contact requests
//! for a *known* public key in a few thousand tries. Rate-limit contact
//! requests server-side (see `MAX_REQUESTS_PER_KEY_PER_HOUR`) or switch
//! NOSPAM_LEN to 4 and accept a 76-char ID.

use std::fmt;
use std::str::FromStr;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const NOSPAM_LEN: usize = 2;
pub const CHECKSUM_LEN: usize = 2;
pub const ID_BYTES: usize = PUBLIC_KEY_LEN + NOSPAM_LEN + CHECKSUM_LEN; // 36
pub const ID_CHARS: usize = ID_BYTES * 2; // 72

/// URI scheme embedded in the QR code. Register this in tauri.conf.json
/// (deep links) so scanning a code opens the app straight to "add contact".
pub const URI_SCHEME: &str = "veil";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContactId {
    public_key: [u8; PUBLIC_KEY_LEN],
    nospam: [u8; NOSPAM_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    BadLength { got: usize },
    NonHex { position: usize },
    ChecksumMismatch,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::BadLength { got } => {
                write!(f, "expected {ID_CHARS} characters, got {got}")
            }
            ParseError::NonHex { position } => {
                write!(f, "invalid character at position {}", position + 1)
            }
            // Shown to the user as "check for a typo" — it is almost always a typo.
            ParseError::ChecksumMismatch => write!(f, "checksum does not match"),
        }
    }
}

impl std::error::Error for ParseError {}

impl ContactId {
    /// Wrap a public key with a freshly generated nospam.
    pub fn new(public_key: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self { public_key, nospam: random_nospam() }
    }

    pub fn with_nospam(public_key: [u8; PUBLIC_KEY_LEN], nospam: [u8; NOSPAM_LEN]) -> Self {
        Self { public_key, nospam }
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    pub fn nospam(&self) -> &[u8; NOSPAM_LEN] {
        &self.nospam
    }

    /// Burn the current ID. The public key — and therefore every existing
    /// conversation — is unaffected; only new contact requests break.
    pub fn rotate_nospam(&mut self) {
        self.nospam = random_nospam();
    }

    /// First byte XORs the even-indexed bytes, second the odd-indexed ones.
    /// Any single-nibble typo lands in exactly one parity class, so every
    /// single-character mistake is caught.
    fn checksum(&self) -> [u8; CHECKSUM_LEN] {
        let mut c = [0u8; CHECKSUM_LEN];
        for (i, b) in self.public_key.iter().chain(self.nospam.iter()).enumerate() {
            c[i % CHECKSUM_LEN] ^= b;
        }
        c
    }

    pub fn to_bytes(&self) -> [u8; ID_BYTES] {
        let mut out = [0u8; ID_BYTES];
        out[..PUBLIC_KEY_LEN].copy_from_slice(&self.public_key);
        out[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + NOSPAM_LEN].copy_from_slice(&self.nospam);
        out[PUBLIC_KEY_LEN + NOSPAM_LEN..].copy_from_slice(&self.checksum());
        out
    }

    /// Payload to encode in the QR code.
    pub fn to_uri(&self) -> String {
        format!("{URI_SCHEME}:{self}")
    }

    /// Grouped into 6-char blocks for on-screen display. Never store this form.
    pub fn to_display_string(&self) -> String {
        self.to_string()
            .as_bytes()
            .chunks(6)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

impl fmt::Display for ContactId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.to_bytes() {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl FromStr for ContactId {
    type Err = ParseError;

    /// Tolerates spaces, dashes, lowercase, and a `veil:` prefix — people
    /// paste these out of chat apps that mangle them.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s
            .strip_prefix(&format!("{URI_SCHEME}://"))
            .or_else(|| s.strip_prefix(&format!("{URI_SCHEME}:")))
            .unwrap_or(s);
        let cleaned: Vec<char> = s
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
            .collect();

        if cleaned.len() != ID_CHARS {
            return Err(ParseError::BadLength { got: cleaned.len() });
        }

        let mut raw = [0u8; ID_BYTES];
        for (i, pair) in cleaned.chunks(2).enumerate() {
            let hi = hex_val(pair[0]).ok_or(ParseError::NonHex { position: i * 2 })?;
            let lo = hex_val(pair[1]).ok_or(ParseError::NonHex { position: i * 2 + 1 })?;
            raw[i] = (hi << 4) | lo;
        }

        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(&raw[..PUBLIC_KEY_LEN]);
        let mut nospam = [0u8; NOSPAM_LEN];
        nospam.copy_from_slice(&raw[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + NOSPAM_LEN]);

        let candidate = ContactId { public_key, nospam };
        if candidate.checksum() != raw[PUBLIC_KEY_LEN + NOSPAM_LEN..] {
            return Err(ParseError::ChecksumMismatch);
        }
        Ok(candidate)
    }
}

fn hex_val(c: char) -> Option<u8> {
    match c {
        '0'..='9' => Some(c as u8 - b'0'),
        'a'..='f' => Some(c as u8 - b'a' + 10),
        'A'..='F' => Some(c as u8 - b'A' + 10),
        _ => None,
    }
}

fn random_nospam() -> [u8; NOSPAM_LEN] {
    use rand::RngCore;
    let mut n = [0u8; NOSPAM_LEN];
    // OsRng, not a seeded PRNG — this feeds an anti-spam check.
    rand::rngs::OsRng.fill_bytes(&mut n);
    n
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ContactId {
        let mut pk = [0u8; 32];
        for (i, b) in pk.iter_mut().enumerate() {
            *b = i as u8;
        }
        ContactId::with_nospam(pk, [0xAB, 0xCD])
    }

    #[test]
    fn renders_72_characters() {
        let s = sample().to_string();
        assert_eq!(s.len(), 72);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_lowercase()));
    }

    #[test]
    fn known_vector() {
        assert_eq!(
            sample().to_string(),
            "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1FABCDABCD"
        );
    }

    #[test]
    fn round_trips() {
        let id = sample();
        assert_eq!(ContactId::from_str(&id.to_string()).unwrap(), id);
        assert_eq!(ContactId::from_str(&id.to_uri()).unwrap(), id);
        assert_eq!(ContactId::from_str(&id.to_display_string()).unwrap(), id);
        assert_eq!(ContactId::from_str(&id.to_string().to_lowercase()).unwrap(), id);
    }

    #[test]
    fn catches_every_single_character_typo() {
        let id = sample();
        let base = id.to_string();
        for i in 0..ID_CHARS {
            for repl in "0123456789ABCDEF".chars() {
                if base.chars().nth(i).unwrap() == repl {
                    continue;
                }
                let mut chars: Vec<char> = base.chars().collect();
                chars[i] = repl;
                let mutated: String = chars.into_iter().collect();
                assert_eq!(
                    ContactId::from_str(&mutated),
                    Err(ParseError::ChecksumMismatch),
                    "typo at index {i} slipped through"
                );
            }
        }
    }

    #[test]
    fn rejects_bad_length_and_non_hex() {
        assert!(matches!(
            ContactId::from_str("ABCD"),
            Err(ParseError::BadLength { .. })
        ));
        let mut s = sample().to_string();
        s.replace_range(0..1, "Z");
        assert!(matches!(
            ContactId::from_str(&s),
            Err(ParseError::NonHex { position: 0 })
        ));
    }

    #[test]
    fn rotating_nospam_preserves_public_key() {
        let mut id = sample();
        let before = *id.public_key();
        id.rotate_nospam();
        assert_eq!(*id.public_key(), before);
    }
}
