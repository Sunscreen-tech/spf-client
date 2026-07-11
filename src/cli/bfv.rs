use alloy::signers::local::PrivateKeySigner;
use anyhow::Result;
use greco_tfhe::{
    ZkpState,
    client::{greco_glwe_def, rlwe_pk_encrypt},
    gen_proof,
    params::RlweParams,
    rlwe_public_key_from_coeffs,
};
use serde::{Deserialize, Serialize};

/// Response shape of GET /bfv_public_key.
#[derive(Deserialize)]
struct BfvPublicKeyResponse {
    pk0_coeffs: Vec<u64>,
    pk1_coeffs: Vec<u64>,
}

/// Mirrors `spf_contracts::BfvCiphertextSubmission` — must stay in sync with the server type.
#[derive(Serialize, Deserialize)]
struct BfvCiphertextSubmission {
    bit_width: u32,
    ct0_coeffs: Vec<u64>,
    ct1_coeffs: Vec<u64>,
    proof: Vec<u8>,
}

/// Fetch the BFV public key coefficient arrays from the SPF endpoint.
pub async fn fetch_bfv_public_key(endpoint: &str) -> Result<(Vec<u64>, Vec<u64>)> {
    let url = format!("{}/bfv_public_key", endpoint);
    let client = super::http::create_http_client(30, endpoint)?;
    let response = client.get(&url).send().await?;
    let response = super::http::check_response_status(response, "BFV public key fetch").await?;
    let pk: BfvPublicKeyResponse = response.json().await?;
    Ok((pk.pk0_coeffs, pk.pk1_coeffs))
}

/// Encrypt a single binary value (0 or 1) as an RLWE ciphertext with a Greco ZK proof
/// and upload it to the `/ciphertexts/bfv` endpoint.
///
/// `bit_width` is the TFHE bit-width label (8/16/32/64) stored server-side; it does not
/// affect the RLWE encryption itself, which always uses a binary plaintext space (t=2).
///
/// Returns the uploaded ciphertext ID.
pub async fn encrypt_and_upload_bfv(
    endpoint: &str,
    value: u64,
    bit_width: u32,
    pk0_coeffs: Vec<u64>,
    pk1_coeffs: Vec<u64>,
    zkp: &ZkpState,
    signer: &PrivateKeySigner,
) -> Result<String> {
    let params = RlweParams::N2048_Q53_T2;

    if value >= params.t {
        anyhow::bail!(
            "value {} is out of the RLWE plaintext space [0, {}); use 0 or 1",
            value,
            params.t
        );
    }

    let pk = rlwe_public_key_from_coeffs(&pk0_coeffs, &pk1_coeffs, &params);

    let (ct, randomness) = rlwe_pk_encrypt(&pk, value, &params);
    let proof = gen_proof(zkp, &pk, &ct, value, &randomness, &params);

    // Extract ct0 (body) and ct1 (mask) coefficients from the GLWE ciphertext.
    let glwe = greco_glwe_def(&params);
    let (mut a_iter, b) = ct.a_b(&glwe);
    let ct1_coeffs: Vec<u64> = a_iter
        .next()
        .unwrap()
        .coeffs()
        .iter()
        .map(|t| u64::from(t.inner()))
        .collect();
    let ct0_coeffs: Vec<u64> = b.coeffs().iter().map(|t| u64::from(t.inner())).collect();

    let submission = BfvCiphertextSubmission {
        bit_width,
        ct0_coeffs,
        ct1_coeffs,
        proof,
    };

    let body = bincode::serialize(&submission)?;

    let auth_header = super::auth::create_ciphertext_upload_auth_header(signer, &body).await?;
    let url = format!("{}/ciphertexts/bfv", endpoint);
    // Use a generous timeout: ZKP proof verification on the server is slow.
    let client = super::http::create_http_client(300, endpoint)?;
    let response = client
        .post(&url)
        .header("spf-identity", auth_header)
        .body(body)
        .send()
        .await?;
    let response = super::http::check_response_status(response, "BFV ciphertext upload").await?;
    let ciphertext_id: String = response.json().await?;
    Ok(crate::core::utils::ensure_hex_prefix(ciphertext_id))
}
