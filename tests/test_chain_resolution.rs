#![cfg(feature = "integration-tests")]

use alloy_chains::NamedChain;
use spf_client::cli::chain::{RpcUrl, resolve_rpc_and_chain};

#[test]
fn test_resolve_rpc_and_chain_web2_mode() {
    // Web2 mode: neither chain nor rpc_url provided
    let result = resolve_rpc_and_chain(None, None);
    assert!(result.is_ok());

    let (rpc_url, chain) = result.unwrap();

    // Should default to local anvil/hardhat
    assert_eq!(rpc_url, "http://127.0.0.1:8545");
    assert!(matches!(chain, NamedChain::AnvilHardhat));
}

#[test]
fn test_resolve_rpc_and_chain_web3_with_chain_only() {
    // Web3 mode: chain provided, no custom RPC
    let result = resolve_rpc_and_chain(None, Some(NamedChain::AnvilHardhat));
    assert!(result.is_ok());

    let (rpc_url, chain) = result.unwrap();

    // Should use chain's default RPC
    assert_eq!(rpc_url, "http://127.0.0.1:8545");
    assert!(matches!(chain, NamedChain::AnvilHardhat));
}

#[test]
fn test_resolve_rpc_and_chain_web3_with_custom_rpc() {
    // Web3 mode: both chain and custom RPC provided
    let custom_rpc = "http://custom-rpc:8545";
    let result = resolve_rpc_and_chain(Some(custom_rpc), Some(NamedChain::Sepolia));
    assert!(result.is_ok());

    let (rpc_url, chain) = result.unwrap();

    // Should use custom RPC
    assert_eq!(rpc_url, custom_rpc);
    assert!(matches!(chain, NamedChain::Sepolia));
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
fn test_chain_rpc_url_method() {
    assert_eq!(
        NamedChain::MonadTestnet.rpc_url().unwrap(),
        "https://testnet-rpc.monad.xyz"
    );
    assert_eq!(
        NamedChain::Sepolia.rpc_url().unwrap(),
        "https://ethereum-sepolia-rpc.publicnode.com"
    );
    assert_eq!(
        NamedChain::AnvilHardhat.rpc_url().unwrap(),
        "http://127.0.0.1:8545"
    );
}
