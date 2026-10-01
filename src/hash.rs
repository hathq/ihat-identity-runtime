use sha2::{Digest, Sha256};

pub(crate) fn digest_fields(domain: &str, fields: &[&[u8]]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain.len().to_be_bytes());
    hash.update(domain.as_bytes());
    for field in fields {
        hash.update(field.len().to_be_bytes());
        hash.update(field);
    }
    hex(&hash.finalize())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}
