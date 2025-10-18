#![cfg(feature = "integration-tests")]

use spf_client::cli::chain::{Chain, resolve_rpc_and_chain};

#[test]
fn test_resolve_rpc_and_chain_web2_mode() {
    // Web2 mode: neither chain nor rpc_url provided
    let result = resolve_rpc_and_chain(None, None);
    assert!(result.is_ok());

    let (rpc_url, chain) = result.unwrap();

    // Should default to localhost
    assert_eq!(rpc_url, "http://127.0.0.1:8545");
    assert!(matches!(chain, Chain::Localhost));
}

#[test]
fn test_resolve_rpc_and_chain_web3_with_chain_only() {
    // Web3 mode: chain provided, no custom RPC
    let result = resolve_rpc_and_chain(None, Some("localhost"));
    assert!(result.is_ok());

    let (rpc_url, chain) = result.unwrap();

    // Should use chain's default RPC
    assert_eq!(rpc_url, "http://127.0.0.1:8545");
    assert!(matches!(chain, Chain::Localhost));
}

#[test]
fn test_resolve_rpc_and_chain_web3_with_custom_rpc() {
    // Web3 mode: both chain and custom RPC provided
    let custom_rpc = "http://custom-rpc:8545";
    let result = resolve_rpc_and_chain(Some(custom_rpc), Some("localhost"));
    assert!(result.is_ok());

    let (rpc_url, chain) = result.unwrap();

    // Should use custom RPC
    assert_eq!(rpc_url, custom_rpc);
    assert!(matches!(chain, Chain::Localhost));
}

#[test]
fn test_resolve_rpc_and_chain_requires_chain_with_custom_rpc() {
    // Error case: RPC provided but no chain
    let result = resolve_rpc_and_chain(Some("http://custom-rpc:8545"), None);
    assert!(result.is_err());

    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("Must specify --chain"));
}

#[test]
fn test_chain_name_method() {
    assert_eq!(Chain::Monad.name(), "Monad");
    assert_eq!(Chain::Sepolia.name(), "Sepolia");
    assert_eq!(Chain::Localhost.name(), "Localhost");
}

#[test]
fn test_chain_rpc_url_method() {
    assert_eq!(Chain::Monad.rpc_url(), "https://testnet-rpc.monad.xyz");
    assert_eq!(
        Chain::Sepolia.rpc_url(),
        "https://ethereum-sepolia-rpc.publicnode.com"
    );
    assert_eq!(Chain::Localhost.rpc_url(), "http://127.0.0.1:8545");
}

#[test]
fn test_chain_from_str() {
    use std::str::FromStr;

    // Case insensitive parsing
    assert!(matches!(Chain::from_str("monad"), Ok(Chain::Monad)));
    assert!(matches!(Chain::from_str("MONAD"), Ok(Chain::Monad)));
    assert!(matches!(Chain::from_str("Monad"), Ok(Chain::Monad)));

    assert!(matches!(Chain::from_str("sepolia"), Ok(Chain::Sepolia)));
    assert!(matches!(Chain::from_str("localhost"), Ok(Chain::Localhost)));

    // Invalid chain
    assert!(Chain::from_str("invalid").is_err());
}

#[test]
fn test_chain_parse_method() {
    // Test idiomatic .parse() method
    assert!(matches!("monad".parse::<Chain>(), Ok(Chain::Monad)));
    assert!(matches!("sepolia".parse::<Chain>(), Ok(Chain::Sepolia)));
    assert!(matches!("localhost".parse::<Chain>(), Ok(Chain::Localhost)));
}
