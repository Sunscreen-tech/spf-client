use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use alloy_chains::NamedChain;
use anyhow::{Context, Result, bail};

pub trait RpcUrl {
    fn rpc_url(&self) -> Result<&str>;
}

impl RpcUrl for NamedChain {
    /// Get RPC URL for the chain
    fn rpc_url(&self) -> Result<&str> {
        match self {
            NamedChain::MonadTestnet => Ok("https://testnet-rpc.monad.xyz"),
            NamedChain::Sepolia => Ok("https://ethereum-sepolia-rpc.publicnode.com"),
            NamedChain::AnvilHardhat => Ok("http://127.0.0.1:8545"),
            _ => bail!("Figuring out RPC URL for {self} is not yet supported"),
        }
    }
}

/// Resolve RPC URL and Chain from optional parameters
///
/// If both rpc_url and chain are provided: uses custom RPC with specified chain
/// If only chain is provided: uses chain's default RPC URL
/// If only rpc_url is provided: errors (must specify which chain)
/// If neither is provided: defaults to Localhost
pub fn resolve_rpc_and_chain(
    rpc_url: Option<&str>,
    chain: Option<&str>,
) -> Result<(String, NamedChain)> {
    match (rpc_url, chain) {
        (Some(url), Some(c)) => {
            let chain = c.parse::<NamedChain>()?;
            Ok((url.to_string(), chain))
        }
        (Some(_), None) => {
            bail!("Must specify --chain (monad/sepolia/localhost) when using custom --rpc-url")
        }
        (None, Some(c)) => {
            let chain = c.parse::<NamedChain>()?;
            Ok((chain.rpc_url()?.to_string(), chain))
        }
        (None, None) => Ok((
            NamedChain::AnvilHardhat.rpc_url()?.to_string(),
            NamedChain::AnvilHardhat,
        )),
    }
}

/// Query chain ID from RPC endpoint and validate it matches expected chain
pub async fn query_and_validate_chain_id(rpc_url: &str, chain: &NamedChain) -> Result<u64> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().context("Invalid RPC URL")?);

    let chain_id = provider
        .get_chain_id()
        .await
        .context(format!("Failed to query chain ID from RPC {}", rpc_url))?;

    // Validate chain ID matches expected value for named chains
    if *chain as u64 != chain_id {
        bail!(
            "Chain ID mismatch: expected {} for {} but got {} from RPC {}",
            *chain as u64,
            chain,
            chain_id,
            rpc_url
        );
    }

    Ok(chain_id)
}

/// Parse an address from hex string
pub fn parse_address(address: &str) -> Result<Address> {
    address
        .parse::<Address>()
        .context(format!("Invalid address: {}", address))
}
