use super::encoding::B256;
use super::error::Result;

pub fn keccak256(data: &[u8]) -> B256 {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    B256(output)
}

pub fn derive_ciphertext_id(ciphertext_bytes: &[u8]) -> String {
    let hash = keccak256(ciphertext_bytes);
    format!("0x{}", hex::encode(hash.as_slice()))
}

pub fn derive_program_id(elf_bytes: &[u8]) -> String {
    let hash = keccak256(elf_bytes);
    format!("0x{}", hex::encode(hash.as_slice()))
}

pub fn derive_result_id(run_handle: &str, index: u8) -> Result<String> {
    let run_bytes = hex::decode(run_handle.trim_start_matches("0x"))?;
    let mut combined = Vec::with_capacity(run_bytes.len() + 1);
    combined.extend_from_slice(&run_bytes);
    combined.push(index);

    let hash = keccak256(&combined);
    Ok(format!("0x{}", hex::encode(hash.as_slice())))
}

/// Ensure a hex string has the "0x" prefix
///
/// Returns the input string as-is if it already starts with "0x",
/// otherwise prepends "0x" to it.
pub fn ensure_hex_prefix(s: impl Into<String>) -> String {
    let s = s.into();
    if s.starts_with("0x") {
        s
    } else {
        format!("0x{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_deterministic() {
        let data = b"test data";
        let hash1 = keccak256(data);
        let hash2 = keccak256(data);
        assert_eq!(hash1.as_slice(), hash2.as_slice());
    }

    #[test]
    fn test_keccak256_different_inputs() {
        let hash1 = keccak256(b"test1");
        let hash2 = keccak256(b"test2");
        assert_ne!(hash1.as_slice(), hash2.as_slice());
    }

    #[test]
    fn test_keccak256_known_value() {
        // Test against known keccak256 hash of empty string
        let hash = keccak256(b"");
        // Keccak256 of empty string
        let expected =
            hex::decode("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
                .unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_derive_ciphertext_id_format() {
        let ct_bytes = vec![0u8; 100];
        let id = derive_ciphertext_id(&ct_bytes);

        // Should start with 0x
        assert!(id.starts_with("0x"));
        // Should be 66 characters (0x + 64 hex chars = 32 bytes)
        assert_eq!(id.len(), 66);
    }

    #[test]
    fn test_derive_ciphertext_id_deterministic() {
        let ct_bytes = vec![1, 2, 3, 4, 5];
        let id1 = derive_ciphertext_id(&ct_bytes);
        let id2 = derive_ciphertext_id(&ct_bytes);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_ciphertext_id_different_inputs() {
        let id1 = derive_ciphertext_id(&[1, 2, 3]);
        let id2 = derive_ciphertext_id(&[1, 2, 4]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_derive_program_id_format() {
        let elf_bytes = vec![0x7F, b'E', b'L', b'F']; // ELF magic
        let id = derive_program_id(&elf_bytes);

        assert!(id.starts_with("0x"));
        assert_eq!(id.len(), 66);
    }

    #[test]
    fn test_derive_program_id_deterministic() {
        let elf_bytes = vec![0u8; 50];
        let id1 = derive_program_id(&elf_bytes);
        let id2 = derive_program_id(&elf_bytes);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_derive_result_id_valid() {
        let run_handle = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let id = derive_result_id(run_handle, 0).unwrap();

        assert!(id.starts_with("0x"));
        assert_eq!(id.len(), 66);
    }

    #[test]
    fn test_derive_result_id_without_prefix() {
        let run_handle = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let id = derive_result_id(run_handle, 0).unwrap();

        assert!(id.starts_with("0x"));
        assert_eq!(id.len(), 66);
    }

    #[test]
    fn test_derive_result_id_different_indices() {
        let run_handle = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let id0 = derive_result_id(run_handle, 0).unwrap();
        let id1 = derive_result_id(run_handle, 1).unwrap();

        assert_ne!(id0, id1);
    }

    #[test]
    fn test_derive_result_id_invalid_hex() {
        let run_handle = "0xZZZZ";
        let result = derive_result_id(run_handle, 0);
        assert!(result.is_err());
    }
}
