//! Hex encoding for on-disk blobs.
//!
//! Deliberately hand-rolled rather than pulled in as a dependency: it is
//! forty lines, it has no failure modes of its own beyond length, and the
//! ciphertexts it handles are binary by definition so nothing readable is lost.
//!
//! Lower case only, so an encoded value has exactly one representation and a
//! file cannot differ from itself by case alone.

use crate::error::{Error, Result};

const HEX: &[u8; 16] = b"0123456789abcdef";

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Malformed("hex string has an odd length".into()));
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for pair in b.chunks(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::Malformed(
            "hex string contains a non-hex character".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn empty_roundtrips() {
        assert_eq!(decode(&encode(&[])).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn rejects_odd_length() {
        assert!(decode("abc").is_err());
    }

    #[test]
    fn rejects_non_hex() {
        assert!(decode("zz").is_err());
        // Whitespace is not silently skipped: a truncated or padded blob must
        // fail loudly rather than decode to something shorter than intended.
        assert!(decode("ab cd").is_err());
    }

    #[test]
    fn uppercase_decodes_to_the_same_bytes() {
        assert_eq!(decode("DEADbeef").unwrap(), decode("deadbeef").unwrap());
    }
}
