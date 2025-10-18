use super::error::{Result, SpfError};
use serde::{Deserialize, Serialize};

// Size constants
pub const ADDRESS_BYTES: usize = 20;
pub const HASH_BYTES: usize = 32;
pub const MAX_PROGRAM_NAME_BYTES: usize = 32;
pub const MAX_ENTRY_POINT_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Address(pub [u8; ADDRESS_BYTES]);

impl Address {
    /// Create Address from a slice. Panics if slice length != ADDRESS_BYTES.
    /// Consider using `try_from_slice` for safer error handling.
    pub fn from_slice(slice: &[u8]) -> Self {
        Self::try_from_slice(slice).expect("Invalid address length")
    }

    /// Try to create Address from a slice. Returns error if slice length != ADDRESS_BYTES.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != ADDRESS_BYTES {
            return Err(SpfError::InvalidAddressLength {
                expected: ADDRESS_BYTES,
                actual: slice.len(),
            });
        }
        let mut arr = [0u8; ADDRESS_BYTES];
        arr.copy_from_slice(slice);
        Ok(Address(arr))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

// Conversions for alloy::primitives::Address (only available in non-WASM builds)
#[cfg(not(target_arch = "wasm32"))]
impl TryFrom<alloy::primitives::Address> for Address {
    type Error = SpfError;

    fn try_from(addr: alloy::primitives::Address) -> Result<Self> {
        Self::try_from_slice(addr.as_slice())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<Address> for alloy::primitives::Address {
    fn from(addr: Address) -> Self {
        alloy::primitives::Address::from_slice(addr.as_slice())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct B256(pub [u8; HASH_BYTES]);

impl B256 {
    /// Create B256 from a slice. Panics if slice length != HASH_BYTES.
    /// Consider using `try_from_slice` for safer error handling.
    pub fn from_slice(slice: &[u8]) -> Self {
        Self::try_from_slice(slice).expect("Invalid hash length")
    }

    /// Try to create B256 from a slice. Returns error if slice length != HASH_BYTES.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != HASH_BYTES {
            return Err(SpfError::InvalidHashLength {
                expected: HASH_BYTES,
                actual: slice.len(),
            });
        }
        let mut arr = [0u8; HASH_BYTES];
        arr.copy_from_slice(slice);
        Ok(B256(arr))
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn repeat_byte(byte: u8) -> Self {
        B256([byte; HASH_BYTES])
    }

    pub const ZERO: Self = B256([0u8; HASH_BYTES]);
}

// Conversions for alloy::primitives::FixedBytes<32> (only available in non-WASM builds)
#[cfg(not(target_arch = "wasm32"))]
impl From<B256> for alloy::primitives::FixedBytes<32> {
    fn from(hash: B256) -> Self {
        alloy::primitives::FixedBytes::<32>::from_slice(hash.as_slice())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl From<alloy::primitives::FixedBytes<32>> for B256 {
    fn from(hash: alloy::primitives::FixedBytes<32>) -> Self {
        B256(hash.0)
    }
}

#[derive(Clone)]
pub enum ParamType {
    Ciphertext { identifier: B256 },
    CiphertextArray { identifiers: Vec<B256> },
    OutputCiphertextArray { bit_width: u8, size: u8 },
    Plaintext { bit_width: u8, value: u128 },
    PlaintextArray { bit_width: u8, values: Vec<u128> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfParameter {
    #[serde(rename = "metaData")]
    pub meta_data: B256,
    pub payload: Vec<B256>,
}

impl From<ParamType> for SpfParameter {
    fn from(value: ParamType) -> Self {
        let mut meta_data = B256::repeat_byte(0xFF);
        match value {
            ParamType::Ciphertext { .. } => {
                meta_data.0[0] = 0;
            }
            ParamType::CiphertextArray { .. } => {
                meta_data.0[0] = 1;
            }
            ParamType::OutputCiphertextArray { bit_width, size } => {
                meta_data.0[0] = 2;
                meta_data.0[1] = bit_width;
                meta_data.0[2] = size;
            }
            ParamType::Plaintext { bit_width, .. } => {
                meta_data.0[0] = 3;
                meta_data.0[1] = bit_width;
            }
            ParamType::PlaintextArray { bit_width, .. } => {
                meta_data.0[0] = 4;
                meta_data.0[1] = bit_width;
            }
        };

        let payload = match value {
            ParamType::Ciphertext { identifier } => {
                vec![identifier]
            }
            ParamType::CiphertextArray { identifiers } => identifiers,
            ParamType::OutputCiphertextArray { .. } => Vec::new(),
            ParamType::Plaintext { value, .. } => {
                let mut item = B256::repeat_byte(0);
                item.0[16..32].copy_from_slice(&value.to_be_bytes());
                vec![item]
            }
            ParamType::PlaintextArray { values, .. } => values
                .into_iter()
                .map(|value| {
                    let mut item = B256::repeat_byte(0);
                    item.0[16..32].copy_from_slice(&value.to_be_bytes());
                    item
                })
                .collect(),
        };

        Self { meta_data, payload }
    }
}

#[derive(Clone)]
pub enum AccessType {
    Admin {
        chain_id: Option<u64>,
        addr: Address,
    },
    Run {
        chain_id: Option<u64>,
        addr: Address,
        lib: B256,
        entry_point: String,
    },
    Decrypt {
        chain_id: Option<u64>,
        addr: Address,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfAccessChange {
    #[serde(rename = "metaData")]
    pub meta_data: B256,
    pub payload: Vec<B256>,
}

impl TryFrom<AccessType> for SpfAccessChange {
    type Error = SpfError;

    fn try_from(value: AccessType) -> std::result::Result<Self, Self::Error> {
        let mut meta_data = B256::repeat_byte(0xFF);
        let (chain_id, addr, lib_and_entry) = match &value {
            AccessType::Admin { chain_id, addr } => {
                meta_data.0[0] = 0;
                (*chain_id, *addr, None)
            }
            AccessType::Run {
                chain_id,
                addr,
                lib,
                entry_point,
            } => {
                // Validate entry point length
                if entry_point.len() > MAX_ENTRY_POINT_BYTES {
                    return Err(SpfError::EntryPointTooLong {
                        len: entry_point.len(),
                        max: MAX_ENTRY_POINT_BYTES,
                    });
                }
                meta_data.0[0] = 1;
                (*chain_id, *addr, Some((*lib, entry_point.clone())))
            }
            AccessType::Decrypt { chain_id, addr } => {
                meta_data.0[0] = 2;
                (*chain_id, *addr, None)
            }
        };

        match chain_id {
            Some(c) => {
                meta_data.0[1] = 0;
                meta_data.0[2..10].copy_from_slice(&c.to_be_bytes());
            }
            None => meta_data.0[1] = 1,
        };

        let mut payload = vec![B256::ZERO];
        payload[0].0[0..ADDRESS_BYTES].copy_from_slice(addr.as_slice());

        if let Some((lib, entry_point)) = lib_and_entry {
            payload.push(lib);
            let mut entry_point_bytes = B256::ZERO;
            entry_point_bytes.0[0..entry_point.len()].copy_from_slice(entry_point.as_bytes());
            payload.push(entry_point_bytes);
        }

        Ok(Self { meta_data, payload })
    }
}

pub fn encode_addr(chain_id: Option<u64>, addr: Address) -> [u8; 33] {
    let mut v = [0; 33];

    if let Some(chain_id) = chain_id {
        v[5..13].copy_from_slice(&chain_id.to_be_bytes());
    } else {
        v[0] = 1;
    }
    v[13..33].copy_from_slice(addr.as_slice());

    v
}

pub fn encode_access(access_type: AccessType) -> Result<Vec<u8>> {
    match access_type {
        AccessType::Admin { chain_id, addr } => {
            Ok([[0].as_slice(), &encode_addr(chain_id, addr)].concat())
        }
        AccessType::Run {
            chain_id,
            addr,
            lib,
            entry_point,
        } => {
            // Validate entry point length
            if entry_point.len() > MAX_ENTRY_POINT_BYTES {
                return Err(SpfError::EntryPointTooLong {
                    len: entry_point.len(),
                    max: MAX_ENTRY_POINT_BYTES,
                });
            }
            Ok([
                [1].as_slice(),
                &encode_addr(chain_id, addr),
                lib.as_slice(),
                &{
                    let mut v = [0; HASH_BYTES];
                    v[0..entry_point.len()].copy_from_slice(entry_point.as_bytes());
                    v
                },
            ]
            .concat())
        }
        AccessType::Decrypt { chain_id, addr } => {
            Ok([[2].as_slice(), &encode_addr(chain_id, addr)].concat())
        }
    }
}

pub fn create_meta_data(bytes: &[u8]) -> Result<B256> {
    if bytes.len() > HASH_BYTES {
        return Err(SpfError::MetadataTooLong {
            len: bytes.len(),
            max: HASH_BYTES,
        });
    }
    let mut data = B256::repeat_byte(0xFF);
    data.0[..bytes.len()].copy_from_slice(bytes);
    Ok(data)
}

pub fn encode_program_name(name: &str) -> Result<B256> {
    let bytes = name.as_bytes();
    if bytes.len() > MAX_PROGRAM_NAME_BYTES {
        return Err(SpfError::ProgramNameTooLong {
            len: bytes.len(),
            max: MAX_PROGRAM_NAME_BYTES,
        });
    }

    let mut result = B256::ZERO;
    result.0[..bytes.len()].copy_from_slice(bytes);
    Ok(result)
}

/// Parse a hex-encoded address string (with or without 0x prefix)
pub fn parse_address_hex(address: &str) -> Result<Address> {
    let addr_hex = address.trim_start_matches("0x");
    let addr_bytes =
        hex::decode(addr_hex).map_err(|e| SpfError::InvalidAddressHex(e.to_string()))?;

    Address::try_from_slice(&addr_bytes)
}

/// Parse a hex-encoded B256 hash string (with or without 0x prefix)
pub fn parse_b256_hex(hash: &str) -> Result<B256> {
    let hash_hex = hash.trim_start_matches("0x");
    let hash_bytes = hex::decode(hash_hex).map_err(|e| SpfError::InvalidHashHex(e.to_string()))?;

    B256::try_from_slice(&hash_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Address tests
    #[test]
    fn test_address_try_from_slice_valid() {
        let bytes = [1u8; ADDRESS_BYTES];
        let addr = Address::try_from_slice(&bytes).unwrap();
        assert_eq!(addr.as_slice(), &bytes);
    }

    #[test]
    fn test_address_try_from_slice_invalid_length_short() {
        let bytes = [1u8; 19];
        let result = Address::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::InvalidAddressLength { .. }
        ));
    }

    #[test]
    fn test_address_try_from_slice_invalid_length_long() {
        let bytes = [1u8; 21];
        let result = Address::try_from_slice(&bytes);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "Invalid address length")]
    fn test_address_from_slice_panics() {
        let bytes = [1u8; 19];
        Address::from_slice(&bytes);
    }

    #[test]
    fn test_parse_address_hex_valid() {
        let hex = "0x1234567890123456789012345678901234567890";
        let addr = parse_address_hex(hex).unwrap();
        assert_eq!(addr.as_slice().len(), ADDRESS_BYTES);
    }

    #[test]
    fn test_parse_address_hex_valid_no_prefix() {
        let hex = "1234567890123456789012345678901234567890";
        let addr = parse_address_hex(hex).unwrap();
        assert_eq!(addr.as_slice().len(), ADDRESS_BYTES);
    }

    #[test]
    fn test_parse_address_hex_invalid_hex() {
        let hex = "0xZZZZ567890123456789012345678901234567890";
        let result = parse_address_hex(hex);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::InvalidAddressHex(_)
        ));
    }

    #[test]
    fn test_parse_address_hex_invalid_length() {
        let hex = "0x1234";
        let result = parse_address_hex(hex);
        assert!(result.is_err());
    }

    // B256 tests
    #[test]
    fn test_b256_try_from_slice_valid() {
        let bytes = [2u8; HASH_BYTES];
        let hash = B256::try_from_slice(&bytes).unwrap();
        assert_eq!(hash.as_slice(), &bytes);
    }

    #[test]
    fn test_b256_try_from_slice_invalid_length() {
        let bytes = [2u8; 31];
        let result = B256::try_from_slice(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::InvalidHashLength { .. }
        ));
    }

    #[test]
    fn test_b256_repeat_byte() {
        let hash = B256::repeat_byte(0xFF);
        assert!(hash.as_slice().iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_b256_zero_constant() {
        assert!(B256::ZERO.as_slice().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_parse_b256_hex_valid() {
        let hex = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let hash = parse_b256_hex(hex).unwrap();
        assert_eq!(hash.as_slice().len(), HASH_BYTES);
    }

    #[test]
    fn test_parse_b256_hex_invalid() {
        let hex = "0x1234"; // Too short
        let result = parse_b256_hex(hex);
        assert!(result.is_err());
    }

    // Encoding tests
    #[test]
    fn test_encode_program_name_valid() {
        let name = "test_program";
        let encoded = encode_program_name(name).unwrap();
        let bytes = name.as_bytes();
        assert_eq!(&encoded.as_slice()[..bytes.len()], bytes);
    }

    #[test]
    fn test_encode_program_name_max_length() {
        let name = "a".repeat(MAX_PROGRAM_NAME_BYTES);
        let encoded = encode_program_name(&name).unwrap();
        assert_eq!(
            &encoded.as_slice()[..MAX_PROGRAM_NAME_BYTES],
            name.as_bytes()
        );
    }

    #[test]
    fn test_encode_program_name_too_long() {
        let name = "a".repeat(MAX_PROGRAM_NAME_BYTES + 1);
        let result = encode_program_name(&name);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::ProgramNameTooLong { .. }
        ));
    }

    #[test]
    fn test_create_meta_data_valid() {
        let data = vec![1, 2, 3, 4];
        let meta = create_meta_data(&data).unwrap();
        assert_eq!(&meta.as_slice()[..4], &[1, 2, 3, 4]);
        assert_eq!(meta.as_slice()[4], 0xFF); // Rest should be 0xFF
    }

    #[test]
    fn test_create_meta_data_too_long() {
        let data = vec![1u8; HASH_BYTES + 1];
        let result = create_meta_data(&data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::MetadataTooLong { .. }
        ));
    }

    #[test]
    fn test_encode_access_admin() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let access = AccessType::Admin {
            chain_id: Some(1),
            addr,
        };
        let encoded = encode_access(access).unwrap();
        assert_eq!(encoded[0], 0); // Admin type
        assert!(encoded.len() > ADDRESS_BYTES);
    }

    #[test]
    fn test_encode_access_decrypt() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let access = AccessType::Decrypt {
            chain_id: None,
            addr,
        };
        let encoded = encode_access(access).unwrap();
        assert_eq!(encoded[0], 2); // Decrypt type
    }

    #[test]
    fn test_encode_access_run_valid() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let lib = B256([2u8; HASH_BYTES]);
        let access = AccessType::Run {
            chain_id: Some(1),
            addr,
            lib,
            entry_point: "main".to_string(),
        };
        let encoded = encode_access(access).unwrap();
        assert_eq!(encoded[0], 1); // Run type
    }

    #[test]
    fn test_encode_access_run_entry_point_too_long() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let lib = B256([2u8; HASH_BYTES]);
        let long_entry = "a".repeat(MAX_ENTRY_POINT_BYTES + 1);
        let access = AccessType::Run {
            chain_id: Some(1),
            addr,
            lib,
            entry_point: long_entry,
        };
        let result = encode_access(access);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::EntryPointTooLong { .. }
        ));
    }

    #[test]
    fn test_encode_addr_with_chain_id() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let encoded = encode_addr(Some(1), addr);
        assert_eq!(encoded.len(), 33);
        assert_eq!(encoded[0], 0); // Has chain ID marker
    }

    #[test]
    fn test_encode_addr_without_chain_id() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let encoded = encode_addr(None, addr);
        assert_eq!(encoded.len(), 33);
        assert_eq!(encoded[0], 1); // No chain ID marker
    }

    // AccessType conversion tests
    #[test]
    fn test_access_type_admin_to_spf_access_change() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let access = AccessType::Admin {
            chain_id: Some(1),
            addr,
        };
        let change: SpfAccessChange = access.try_into().unwrap();
        assert_eq!(change.meta_data.0[0], 0); // Admin type
    }

    #[test]
    fn test_access_type_decrypt_to_spf_access_change() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let access = AccessType::Decrypt {
            chain_id: None,
            addr,
        };
        let change: SpfAccessChange = access.try_into().unwrap();
        assert_eq!(change.meta_data.0[0], 2); // Decrypt type
    }

    #[test]
    fn test_access_type_run_to_spf_access_change() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let lib = B256([2u8; HASH_BYTES]);
        let access = AccessType::Run {
            chain_id: Some(1),
            addr,
            lib,
            entry_point: "main".to_string(),
        };
        let change: SpfAccessChange = access.try_into().unwrap();
        assert_eq!(change.meta_data.0[0], 1); // Run type
        assert_eq!(change.payload.len(), 3); // addr + lib + entry_point
    }

    #[test]
    fn test_access_type_run_entry_point_validation() {
        let addr = Address([1u8; ADDRESS_BYTES]);
        let lib = B256([2u8; HASH_BYTES]);
        let long_entry = "a".repeat(MAX_ENTRY_POINT_BYTES + 1);
        let access = AccessType::Run {
            chain_id: Some(1),
            addr,
            lib,
            entry_point: long_entry,
        };
        let result: std::result::Result<SpfAccessChange, SpfError> = access.try_into();
        assert!(result.is_err());
    }

    // ParamType conversion tests
    #[test]
    fn test_param_type_ciphertext() {
        let id = B256([1u8; HASH_BYTES]);
        let param = ParamType::Ciphertext { identifier: id };
        let spf_param: SpfParameter = param.into();
        assert_eq!(spf_param.meta_data.0[0], 0); // Ciphertext type
        assert_eq!(spf_param.payload.len(), 1);
    }

    #[test]
    fn test_param_type_plaintext() {
        let param = ParamType::Plaintext {
            bit_width: 16,
            value: 42,
        };
        let spf_param: SpfParameter = param.into();
        assert_eq!(spf_param.meta_data.0[0], 3); // Plaintext type
        assert_eq!(spf_param.meta_data.0[1], 16); // Bit width
    }
}
