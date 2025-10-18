use super::error::{Result, SpfError};
use parasol_runtime::{
    DEFAULT_128, Encryption, L1GlweCiphertext, PublicKey, PublicOneTimePad, SecretOneTimePad,
    decrypt_one_time_pad, fluent::PackedDynamicInt, fluent::PackedDynamicUInt,
    generate_one_time_pad, safe_bincode, safe_bincode::GetSize,
};
use sunscreen_tfhe::entities::Polynomial;

// Valid bit widths for FHE operations
const VALID_BIT_WIDTHS: [u8; 4] = [8, 16, 32, 64];

fn validate_bit_width(bits: u8) -> Result<()> {
    if !VALID_BIT_WIDTHS.contains(&bits) {
        return Err(SpfError::InvalidBitWidth { width: bits });
    }
    Ok(())
}

fn validate_unsigned_value_fits(val: u64, bits: u8) -> Result<()> {
    if bits < 64 && val >= (1u64 << bits) {
        return Err(SpfError::ValueOutOfRange { value: val, bits });
    }
    Ok(())
}

fn validate_signed_value_fits(val: i64, bits: u8) -> Result<()> {
    if bits < 64 {
        let min = -(1i64 << (bits - 1));
        let max = (1i64 << (bits - 1)) - 1;
        if val < min || val > max {
            return Err(SpfError::ValueOutOfRange {
                value: val as u64,
                bits,
            });
        }
    }
    Ok(())
}

pub fn encrypt_unsigned_core(val: u64, bits: u8, pk: &PublicKey) -> Result<Vec<u8>> {
    validate_bit_width(bits)?;
    validate_unsigned_value_fits(val, bits)?;

    let enc = Encryption::default();
    let ct: PackedDynamicUInt<L1GlweCiphertext> =
        PackedDynamicUInt::encrypt(val as u128, &enc, pk, bits as usize);
    Ok(bincode::serialize(&ct)?)
}

pub fn encrypt_signed_core(val: i64, bits: u8, pk: &PublicKey) -> Result<Vec<u8>> {
    validate_bit_width(bits)?;
    validate_signed_value_fits(val, bits)?;

    let enc = Encryption::default();
    let ct: PackedDynamicInt<L1GlweCiphertext> =
        PackedDynamicInt::encrypt(val as i128, &enc, pk, bits as usize);
    Ok(bincode::serialize(&ct)?)
}

pub struct OtpKeypairCore {
    pub public_otp: Vec<u8>,
    pub secret_otp: Vec<u8>,
}

pub fn generate_otp_core(pk: &PublicKey) -> Result<OtpKeypairCore> {
    let enc = Encryption::default();
    let (public, secret) = generate_one_time_pad(&DEFAULT_128, &enc, pk);

    Ok(OtpKeypairCore {
        public_otp: bincode::serialize(&public)?,
        secret_otp: bincode::serialize(&secret)?,
    })
}

pub fn otp_decrypt_unsigned_core(
    poly_bytes: &[u8],
    secret_otp_bytes: &[u8],
    bits: u8,
) -> Result<u64> {
    validate_bit_width(bits)?;

    let poly = bincode::deserialize::<Polynomial<u64>>(poly_bytes)?;
    let secret = safe_bincode::deserialize::<SecretOneTimePad>(secret_otp_bytes, &DEFAULT_128)?;

    let decrypted_poly = decrypt_one_time_pad(&poly, &secret);

    let mut result = 0u64;
    for i in 0..(bits as usize) {
        result |= (decrypted_poly.coeffs()[i] as u64) << i;
    }

    Ok(result)
}

pub fn otp_decrypt_signed_core(
    poly_bytes: &[u8],
    secret_otp_bytes: &[u8],
    bits: u8,
) -> Result<i64> {
    validate_bit_width(bits)?;

    let poly = bincode::deserialize::<Polynomial<u64>>(poly_bytes)?;
    let secret = safe_bincode::deserialize::<SecretOneTimePad>(secret_otp_bytes, &DEFAULT_128)?;

    let decrypted_poly = decrypt_one_time_pad(&poly, &secret);

    let mut unsigned_result = 0u64;
    for i in 0..(bits as usize) {
        unsigned_result |= (decrypted_poly.coeffs()[i] as u64) << i;
    }

    let sign_bit = 1u64 << (bits - 1);
    if unsigned_result & sign_bit != 0 {
        let mask = !((1u64 << bits) - 1);
        Ok((unsigned_result | mask) as i64)
    } else {
        Ok(unsigned_result as i64)
    }
}

pub fn public_otp_size() -> u32 {
    PublicOneTimePad::get_size(&DEFAULT_128) as u32
}

pub fn secret_otp_size() -> u32 {
    SecretOneTimePad::get_size(&DEFAULT_128) as u32
}

pub fn parse_polynomial_to_value(poly_bytes: &[u8], bit_width: u8, signed: bool) -> Result<i64> {
    validate_bit_width(bit_width)?;

    let poly: Polynomial<u64> = bincode::deserialize(poly_bytes)?;

    // Reconstruct value from polynomial coefficients
    // Each non-zero coefficient represents a set bit
    let mut unsigned_result = 0u64;
    for i in 0..(bit_width as usize).min(poly.coeffs().len()) {
        if poly.coeffs()[i] != 0 {
            unsigned_result |= 1u64 << i;
        }
    }

    // Handle signed conversion if needed
    if signed && bit_width < 64 {
        let sign_bit = 1u64 << (bit_width - 1);
        if unsigned_result & sign_bit != 0 {
            // Negative number - sign extend
            let mask = !((1u64 << bit_width) - 1);
            return Ok((unsigned_result | mask) as i64);
        }
    }

    Ok(unsigned_result as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Validation function tests
    #[test]
    fn test_validate_bit_width_8() {
        assert!(validate_bit_width(8).is_ok());
    }

    #[test]
    fn test_validate_bit_width_16() {
        assert!(validate_bit_width(16).is_ok());
    }

    #[test]
    fn test_validate_bit_width_32() {
        assert!(validate_bit_width(32).is_ok());
    }

    #[test]
    fn test_validate_bit_width_64() {
        assert!(validate_bit_width(64).is_ok());
    }

    #[test]
    fn test_validate_bit_width_invalid() {
        assert!(validate_bit_width(0).is_err());
        assert!(validate_bit_width(1).is_err());
        assert!(validate_bit_width(7).is_err());
        assert!(validate_bit_width(15).is_err());
        assert!(validate_bit_width(31).is_err());
        assert!(validate_bit_width(63).is_err());
        assert!(validate_bit_width(128).is_err());
        assert!(validate_bit_width(255).is_err());
    }

    #[test]
    fn test_validate_bit_width_error_message() {
        let result = validate_bit_width(7);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::InvalidBitWidth { width: 7 }
        ));
    }

    // Value range validation tests for unsigned
    #[test]
    fn test_validate_unsigned_value_fits_8bit() {
        assert!(validate_unsigned_value_fits(255, 8).is_ok());
        assert!(validate_unsigned_value_fits(0, 8).is_ok());
        assert!(validate_unsigned_value_fits(128, 8).is_ok());
    }

    #[test]
    fn test_validate_unsigned_value_out_of_range_8bit() {
        let result = validate_unsigned_value_fits(256, 8);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::ValueOutOfRange { .. }
        ));
    }

    #[test]
    fn test_validate_unsigned_value_fits_16bit() {
        assert!(validate_unsigned_value_fits(65535, 16).is_ok());
        assert!(validate_unsigned_value_fits(32768, 16).is_ok());
    }

    #[test]
    fn test_validate_unsigned_value_out_of_range_16bit() {
        assert!(validate_unsigned_value_fits(65536, 16).is_err());
    }

    #[test]
    fn test_validate_unsigned_value_fits_32bit() {
        assert!(validate_unsigned_value_fits(0xFFFFFFFF, 32).is_ok());
    }

    #[test]
    fn test_validate_unsigned_value_out_of_range_32bit() {
        assert!(validate_unsigned_value_fits(0x100000000, 32).is_err());
    }

    #[test]
    fn test_validate_unsigned_value_fits_64bit() {
        // Any u64 should fit in 64 bits
        assert!(validate_unsigned_value_fits(u64::MAX, 64).is_ok());
        assert!(validate_unsigned_value_fits(0, 64).is_ok());
    }

    // Value range validation tests for signed
    #[test]
    fn test_validate_signed_value_fits_8bit() {
        assert!(validate_signed_value_fits(127, 8).is_ok());
        assert!(validate_signed_value_fits(-128, 8).is_ok());
        assert!(validate_signed_value_fits(0, 8).is_ok());
    }

    #[test]
    fn test_validate_signed_value_out_of_range_positive() {
        let result = validate_signed_value_fits(128, 8);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpfError::ValueOutOfRange { .. }
        ));
    }

    #[test]
    fn test_validate_signed_value_out_of_range_negative() {
        let result = validate_signed_value_fits(-129, 8);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_signed_value_fits_16bit() {
        assert!(validate_signed_value_fits(32767, 16).is_ok());
        assert!(validate_signed_value_fits(-32768, 16).is_ok());
    }

    #[test]
    fn test_validate_signed_value_out_of_range_16bit() {
        assert!(validate_signed_value_fits(32768, 16).is_err());
        assert!(validate_signed_value_fits(-32769, 16).is_err());
    }

    #[test]
    fn test_validate_signed_value_fits_64bit() {
        // Any i64 should fit in 64 bits
        assert!(validate_signed_value_fits(i64::MAX, 64).is_ok());
        assert!(validate_signed_value_fits(i64::MIN, 64).is_ok());
    }

    // OTP size tests
    #[test]
    fn test_public_otp_size() {
        let size = public_otp_size();
        assert!(size > 0);
    }

    #[test]
    fn test_secret_otp_size() {
        let size = secret_otp_size();
        assert!(size > 0);
    }

    // Note: Testing actual encryption/decryption requires a valid PublicKey
    // which depends on parasol_runtime. These tests focus on validation.
    // Integration tests should cover actual encryption/decryption workflows.
}
