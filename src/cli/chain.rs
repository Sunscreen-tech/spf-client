use alloy::primitives::Address;
use alloy::providers::{Provider, ProviderBuilder};
use anyhow::{Context, Result, bail};

/// Supported named chains
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chain {
    Monad,
    Sepolia,
    Localhost,
}

impl std::str::FromStr for Chain {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "monad" => Ok(Chain::Monad),
            "sepolia" => Ok(Chain::Sepolia),
            "localhost" => Ok(Chain::Localhost),
            _ => bail!(
                "Unsupported chain '{}'. Supported chains: monad, sepolia, localhost",
                s
            ),
        }
    }
}

impl Chain {
    /// Get RPC URL for the chain
    pub fn rpc_url(&self) -> &'static str {
        match self {
            Chain::Monad => "https://testnet-rpc.monad.xyz",
            Chain::Sepolia => "https://ethereum-sepolia-rpc.publicnode.com",
            Chain::Localhost => "http://127.0.0.1:8545",
        }
    }

    /// Get expected chain ID (for validation)
    pub fn expected_chain_id(&self) -> Option<u64> {
        match self {
            Chain::Monad => Some(10143),
            Chain::Sepolia => Some(11155111),
            Chain::Localhost => None, // Don't validate localhost chain ID (varies by tool)
        }
    }

    /// Get chain ID for hardcoded chains (used by check operations without RPC)
    ///
    /// Returns None for localhost since the chain ID varies by local setup.
    /// For localhost, use grant operations which query the RPC to get the actual chain ID.
    pub fn chain_id(&self) -> Option<u64> {
        match self {
            Chain::Monad => Some(10143),
            Chain::Sepolia => Some(11155111),
            Chain::Localhost => None, // Varies by local setup
        }
    }

    /// Get human-readable chain name
    pub fn name(&self) -> &'static str {
        match self {
            Chain::Monad => "Monad",
            Chain::Sepolia => "Sepolia",
            Chain::Localhost => "Localhost",
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
) -> Result<(String, Chain)> {
    match (rpc_url, chain) {
        (Some(url), Some(c)) => {
            let chain = c.parse::<Chain>()?;
            Ok((url.to_string(), chain))
        }
        (Some(_), None) => {
            bail!("Must specify --chain (monad/sepolia/localhost) when using custom --rpc-url")
        }
        (None, Some(c)) => {
            let chain = c.parse::<Chain>()?;
            Ok((chain.rpc_url().to_string(), chain))
        }
        (None, None) => Ok((Chain::Localhost.rpc_url().to_string(), Chain::Localhost)),
    }
}

/// Query chain ID from RPC endpoint and validate it matches expected chain
pub async fn query_and_validate_chain_id(rpc_url: &str, chain: &Chain) -> Result<u64> {
    let provider = ProviderBuilder::new().connect_http(rpc_url.parse().context("Invalid RPC URL")?);

    let chain_id = provider
        .get_chain_id()
        .await
        .context(format!("Failed to query chain ID from RPC {}", rpc_url))?;

    // Validate chain ID matches expected value for named chains
    if let Some(expected) = chain.expected_chain_id()
        && expected != chain_id
    {
        bail!(
            "Chain ID mismatch: expected {} for {} but got {} from RPC {}",
            expected,
            chain.name(),
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
