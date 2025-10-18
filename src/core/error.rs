use thiserror::Error;

#[derive(Error, Debug)]
pub enum SpfError {
    #[error("Invalid address length: expected {expected} bytes, got {actual}")]
    InvalidAddressLength { expected: usize, actual: usize },

    #[error("Invalid hash length: expected {expected} bytes, got {actual}")]
    InvalidHashLength { expected: usize, actual: usize },

    #[error("Program name too long: {len} bytes (max {max} bytes)")]
    ProgramNameTooLong { len: usize, max: usize },

    #[error("Entry point name too long: {len} bytes (max {max} bytes)")]
    EntryPointTooLong { len: usize, max: usize },

    #[error("Metadata too long: {len} bytes (max {max} bytes)")]
    MetadataTooLong { len: usize, max: usize },

    #[error("Invalid bit width: {width}. Must be 8, 16, 32, or 64")]
    InvalidBitWidth { width: u8 },

    #[error("Value {value} does not fit in {bits} bits")]
    ValueOutOfRange { value: u64, bits: u8 },

    #[error("Client not initialized. Call initialize() first")]
    ClientNotInitialized,

    #[error("Client already initialized")]
    ClientAlreadyInitialized,

    #[error("Failed to fetch public key: {0}")]
    PublicKeyFetch(String),

    #[error("System time error: {0}")]
    SystemTime(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("Invalid address hex: {0}")]
    InvalidAddressHex(String),

    #[error("Invalid hash hex: {0}")]
    InvalidHashHex(String),

    #[error("Parasol runtime error: {0}")]
    ParasolRuntime(String),

    #[error("{0}")]
    Other(String),
}

// Implement From for parasol_runtime::Error
impl From<parasol_runtime::Error> for SpfError {
    fn from(err: parasol_runtime::Error) -> Self {
        SpfError::ParasolRuntime(err.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SpfError>;

#[cfg(test)]
mod tests {
    use super::*;

    // Test error display messages
    #[test]
    fn test_invalid_address_length_display() {
        let err = SpfError::InvalidAddressLength {
            expected: 20,
            actual: 10,
        };
        let msg = format!("{}", err);
        assert_eq!(msg, "Invalid address length: expected 20 bytes, got 10");
    }

    #[test]
    fn test_invalid_hash_length_display() {
        let err = SpfError::InvalidHashLength {
            expected: 32,
            actual: 16,
        };
        let msg = format!("{}", err);
        assert_eq!(msg, "Invalid hash length: expected 32 bytes, got 16");
    }

    #[test]
    fn test_program_name_too_long_display() {
        let err = SpfError::ProgramNameTooLong { len: 50, max: 32 };
        let msg = format!("{}", err);
        assert_eq!(msg, "Program name too long: 50 bytes (max 32 bytes)");
    }

    #[test]
    fn test_entry_point_too_long_display() {
        let err = SpfError::EntryPointTooLong { len: 40, max: 32 };
        let msg = format!("{}", err);
        assert_eq!(msg, "Entry point name too long: 40 bytes (max 32 bytes)");
    }

    #[test]
    fn test_metadata_too_long_display() {
        let err = SpfError::MetadataTooLong { len: 100, max: 64 };
        let msg = format!("{}", err);
        assert_eq!(msg, "Metadata too long: 100 bytes (max 64 bytes)");
    }

    #[test]
    fn test_invalid_bit_width_display() {
        let err = SpfError::InvalidBitWidth { width: 7 };
        let msg = format!("{}", err);
        assert_eq!(msg, "Invalid bit width: 7. Must be 8, 16, 32, or 64");
    }

    #[test]
    fn test_value_out_of_range_display() {
        let err = SpfError::ValueOutOfRange {
            value: 256,
            bits: 8,
        };
        let msg = format!("{}", err);
        assert_eq!(msg, "Value 256 does not fit in 8 bits");
    }

    #[test]
    fn test_client_not_initialized_display() {
        let err = SpfError::ClientNotInitialized;
        let msg = format!("{}", err);
        assert_eq!(msg, "Client not initialized. Call initialize() first");
    }

    #[test]
    fn test_client_already_initialized_display() {
        let err = SpfError::ClientAlreadyInitialized;
        let msg = format!("{}", err);
        assert_eq!(msg, "Client already initialized");
    }

    #[test]
    fn test_public_key_fetch_display() {
        let err = SpfError::PublicKeyFetch("network timeout".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "Failed to fetch public key: network timeout");
    }

    #[test]
    fn test_system_time_display() {
        let err = SpfError::SystemTime("clock went backwards".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "System time error: clock went backwards");
    }

    #[test]
    fn test_invalid_address_hex_display() {
        let err = SpfError::InvalidAddressHex("wrong length".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "Invalid address hex: wrong length");
    }

    #[test]
    fn test_invalid_hash_hex_display() {
        let err = SpfError::InvalidHashHex("bad format".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "Invalid hash hex: bad format");
    }

    #[test]
    fn test_parasol_runtime_display() {
        let err = SpfError::ParasolRuntime("computation failed".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "Parasol runtime error: computation failed");
    }

    #[test]
    fn test_other_display() {
        let err = SpfError::Other("custom error".to_string());
        let msg = format!("{}", err);
        assert_eq!(msg, "custom error");
    }

    // Test From conversions
    #[test]
    fn test_from_hex_error() {
        let hex_err = hex::FromHexError::InvalidHexCharacter { c: 'Z', index: 0 };
        let spf_err: SpfError = hex_err.into();
        assert!(matches!(spf_err, SpfError::HexDecode(_)));
        let msg = format!("{}", spf_err);
        assert!(msg.contains("Hex decoding error"));
    }

    // Test Debug trait
    #[test]
    fn test_error_is_debuggable() {
        let err = SpfError::InvalidBitWidth { width: 7 };
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("InvalidBitWidth"));
        assert!(debug_str.contains("7"));
    }

    #[test]
    fn test_error_is_debuggable_with_string() {
        let err = SpfError::PublicKeyFetch("test error".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("PublicKeyFetch"));
        assert!(debug_str.contains("test error"));
    }

    // Test that errors can be compared (useful for error handling)
    #[test]
    fn test_error_variants_distinct() {
        let err1 = SpfError::ClientNotInitialized;
        let err2 = SpfError::ClientAlreadyInitialized;
        assert!(format!("{}", err1) != format!("{}", err2));
    }

    // Test error with different parameter values
    #[test]
    fn test_value_out_of_range_different_values() {
        let err1 = SpfError::ValueOutOfRange {
            value: 256,
            bits: 8,
        };
        let err2 = SpfError::ValueOutOfRange {
            value: 65536,
            bits: 16,
        };
        assert_ne!(format!("{}", err1), format!("{}", err2));
    }

    #[test]
    fn test_invalid_bit_width_different_widths() {
        let err1 = SpfError::InvalidBitWidth { width: 7 };
        let err2 = SpfError::InvalidBitWidth { width: 15 };
        let msg1 = format!("{}", err1);
        let msg2 = format!("{}", err2);
        assert!(msg1.contains("7"));
        assert!(msg2.contains("15"));
        assert_ne!(msg1, msg2);
    }

    // Test that Result type alias works correctly
    #[test]
    #[allow(clippy::unnecessary_literal_unwrap)]
    fn test_result_type_alias_ok() {
        let result: Result<i32> = Ok(42);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_result_type_alias_err() {
        let result: Result<i32> = Err(SpfError::ClientNotInitialized);
        assert!(result.is_err());
        match result {
            Err(SpfError::ClientNotInitialized) => {}
            _ => panic!("Expected ClientNotInitialized error"),
        }
    }

    // Test error message content for validation errors
    #[test]
    fn test_invalid_address_length_contains_values() {
        let err = SpfError::InvalidAddressLength {
            expected: 20,
            actual: 15,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("20"));
        assert!(msg.contains("15"));
    }

    #[test]
    fn test_invalid_hash_length_contains_values() {
        let err = SpfError::InvalidHashLength {
            expected: 32,
            actual: 20,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("32"));
        assert!(msg.contains("20"));
    }
}
