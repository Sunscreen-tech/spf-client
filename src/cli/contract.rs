use alloy::primitives::{Address, B256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::sol;
use anyhow::{Context, Result, bail};

// Contract interface for querying SPF program metadata
sol! {
    #[sol(rpc)]
    interface ISpfSingleProgram {
        function getProgramName() external view returns (bytes32);
        function getLibraryHash() external view returns (bytes32);
    }
}

/// Query contract for program name and library hash
pub async fn query_contract_metadata(
    contract_address: Address,
    rpc_url: &str,
) -> Result<(B256, B256)> {
    use tokio::try_join;

    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().context("Invalid RPC URL")?);

    // Check contract exists
    let code = provider
        .get_code_at(contract_address)
        .await
        .context(format!(
            "Failed to check if contract exists at {:?}",
            contract_address
        ))?;

    if code.is_empty() {
        bail!("No contract deployed at address {:?}", contract_address);
    }

    let contract = ISpfSingleProgram::new(contract_address, provider);

    // Make both RPC calls concurrently for better performance
    let library_hash_builder = contract.getLibraryHash();
    let program_name_builder = contract.getProgramName();
    let library_hash_call = library_hash_builder.call();
    let program_name_call = program_name_builder.call();
    let (library_hash, program_name) =
        try_join!(library_hash_call, program_name_call).context(format!(
        "Failed to query contract at {:?} - contract must implement ISpfSingleProgram interface",
        contract_address
    ))?;

    Ok((library_hash, program_name))
}

/// Convert bytes32 to string (ASCII encoded)
pub fn bytes32_to_string(bytes: B256) -> String {
    let bytes_slice = bytes.as_slice();
    let end = bytes_slice.iter().position(|&b| b == 0).unwrap_or(32);
    String::from_utf8_lossy(&bytes_slice[..end]).to_string()
}
