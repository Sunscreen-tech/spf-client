// EIP-712 type definitions for SPF authentication
//
// These types MUST match the TypeScript implementation exactly to ensure
// compatible EIP-712 signatures. Any mismatch in type names, field names,
// or field types will cause signature verification to fail on the server.

use alloy::dyn_abi::Eip712Domain;
use alloy::sol;
use alloy::sol_types::eip712_domain;

/// EIP-712 domain separator for all SPF authentication messages
pub const AUTH_DOMAIN: Eip712Domain = eip712_domain! {
    name: "SPFIdentityHeader",
    version: "1",
};

sol! {
    /// Entry in an access control change request
    ///
    /// Used as a nested type in AccessChangeAuthentication
    #[derive(Debug, PartialEq)]
    struct AccessChangeEntry {
        string accessType;
        address accessAssignee;
        bool isAssigneeContract;
        uint64 chainIdWhenApplicable;
        string additionalDataWhenApplicable;
    }

    /// Authentication for uploading a ciphertext to SPF
    ///
    /// The signer proves ownership of the entity address and integrity
    /// of the ciphertext by signing the hash of the ciphertext bytes.
    #[derive(Debug, PartialEq)]
    struct CiphertextUploadAuthentication {
        address entity;
        uint64 timestampMillis;
        bytes32 ciphertextHash;
    }

    /// Authentication for downloading a ciphertext from SPF
    ///
    /// The signer proves ownership of the entity address. The server
    /// will verify the signer has decrypt access to the requested ciphertext.
    #[derive(Debug, PartialEq)]
    struct CiphertextDownloadAuthentication {
        address entity;
        uint64 timestampMillis;
    }

    /// Authentication for requesting threshold decryption
    ///
    /// The signer proves ownership of the entity address and specifies
    /// which ciphertext should be decrypted.
    #[derive(Debug, PartialEq)]
    struct DecryptionAuthentication {
        address entity;
        uint64 timestampMillis;
        bytes32 ciphertextId;
    }

    /// Authentication for modifying access control lists
    ///
    /// The signer proves ownership of the entity address and specifies
    /// the ciphertext and access changes to apply.
    #[derive(Debug, PartialEq)]
    struct AccessChangeAuthentication {
        address entity;
        uint64 timestampMillis;
        bytes32 ciphertextId;
        AccessChangeEntry[] accessChanges;
    }

    /// Authentication for requesting ciphertext reencryption with OTP
    ///
    /// The signer proves ownership of the entity address and provides
    /// the hash of the one-time pad for reencryption.
    #[derive(Debug, PartialEq)]
    struct ReencryptionAuthentication {
        address entity;
        uint64 timestampMillis;
        bytes32 oneTimePadHash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, FixedBytes};

    #[test]
    fn test_ciphertext_upload_auth_construction() {
        let msg = CiphertextUploadAuthentication {
            entity: Address::ZERO,
            timestampMillis: 1234567890,
            ciphertextHash: FixedBytes::ZERO,
        };
        assert_eq!(msg.timestampMillis, 1234567890);
    }

    #[test]
    fn test_ciphertext_download_auth_construction() {
        let msg = CiphertextDownloadAuthentication {
            entity: Address::ZERO,
            timestampMillis: 1234567890,
        };
        assert_eq!(msg.timestampMillis, 1234567890);
    }

    #[test]
    fn test_decryption_auth_construction() {
        let msg = DecryptionAuthentication {
            entity: Address::ZERO,
            timestampMillis: 1234567890,
            ciphertextId: FixedBytes::ZERO,
        };
        assert_eq!(msg.timestampMillis, 1234567890);
    }

    #[test]
    fn test_access_change_auth_construction() {
        let entry = AccessChangeEntry {
            accessType: "Admin".to_string(),
            accessAssignee: Address::ZERO,
            isAssigneeContract: false,
            chainIdWhenApplicable: 0,
            additionalDataWhenApplicable: "".to_string(),
        };

        let msg = AccessChangeAuthentication {
            entity: Address::ZERO,
            timestampMillis: 1234567890,
            ciphertextId: FixedBytes::ZERO,
            accessChanges: vec![entry],
        };
        assert_eq!(msg.timestampMillis, 1234567890);
        assert_eq!(msg.accessChanges.len(), 1);
    }

    #[test]
    fn test_reencryption_auth_construction() {
        let msg = ReencryptionAuthentication {
            entity: Address::ZERO,
            timestampMillis: 1234567890,
            oneTimePadHash: FixedBytes::ZERO,
        };
        assert_eq!(msg.timestampMillis, 1234567890);
    }
}
