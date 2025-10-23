use alloy_chains::NamedChain;
use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use spf_client::{cli, client};
use std::fs;
use tracing::{debug, info};

#[derive(ValueEnum, Clone, Debug)]
enum Signedness {
    Signed,
    Unsigned,
}

const RUN_SUBMIT_HELP: &str = r#"Submit a program run

Parameters are JSON-encoded arrays. Supported types:
  ciphertext
    {"type":"ciphertext","id":"0x..."}
  ciphertext_array
    {"type":"ciphertext_array","ids":["0x...","0x..."]}
  plaintext
    {"type":"plaintext","bit_width":16,"value":42}
  plaintext_array
    {"type":"plaintext_array","bit_width":16,"values":[1,2,3]}
  output_ciphertext_array
    {"type":"output_ciphertext_array","bit_width":8,"size":1}

Example:
  [{"type":"ciphertext_array","ids":["0x..."]},
   {"type":"plaintext","bit_width":16,"value":42},
   {"type":"output_ciphertext_array","bit_width":8,"size":1}]
"#;

#[derive(Parser)]
#[command(name = "spf")]
#[command(about = "SPF (Secure Processing Framework) CLI client")]
#[command(
    long_about = "SPF (Secure Processing Framework) CLI client\n\nSet RUST_LOG environment variable for verbose output (e.g., RUST_LOG=info or RUST_LOG=debug)"
)]
struct Cli {
    /// SPF endpoint URL
    #[arg(long, default_value = "https://spf.sunscreen.tech", hide = true)]
    endpoint: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Upload a ciphertext to the SPF network
    UploadCiphertext {
        /// Path to ciphertext file
        #[arg(long)]
        file: String,

        /// Wallet private key
        #[arg(long)]
        private_key: String,
    },

    /// Upload a program to the SPF network
    UploadProgram {
        /// Path to SPF program file
        #[arg(long)]
        file: String,
    },

    /// Access control operations
    #[command(subcommand)]
    Access(AccessCommand),

    /// Request threshold decryption of a ciphertext
    Decrypt {
        /// Ciphertext ID
        #[arg(long)]
        ciphertext_id: String,

        /// Wallet private key
        #[arg(long)]
        private_key: String,

        /// Bit width (8/16/32/64)
        #[arg(long)]
        bit_width: u8,

        /// Value sign
        #[arg(long, value_enum)]
        sign: Signedness,
    },

    /// Generate a ciphertext locally
    GenerateCiphertext {
        /// Plaintext value to encrypt
        #[arg(long)]
        value: i64,

        /// Bit width (8, 16, 32, or 64)
        #[arg(long)]
        bits: u8,

        /// Output file path (required unless --upload is used)
        #[arg(long)]
        output: Option<String>,

        /// Upload ciphertext to SPF service after generation
        #[arg(long, default_value = "false")]
        upload: bool,

        /// Wallet private key.
        /// Required when --upload is used
        #[arg(long)]
        private_key: Option<String>,
    },

    /// Generate a new wallet for testing (hidden command)
    #[command(hide = true)]
    NewWallet,

    /// Execute FHE programs
    #[command(subcommand)]
    Run(RunCommand),
}

#[derive(Subcommand)]
enum RunCommand {
    /// Submit a program run
    #[command(long_about = RUN_SUBMIT_HELP)]
    Submit {
        /// Library identifier (program hash)
        #[arg(long)]
        library: String,

        /// Program entry point name
        #[arg(long)]
        program: String,

        /// JSON-encoded parameters array
        #[arg(long)]
        parameters: String,

        /// Wallet private key
        #[arg(long)]
        private_key: String,
    },

    /// Check status of a run
    CheckStatus {
        /// Run handle from submit command
        #[arg(long)]
        run_handle: String,

        /// Output full JSON response
        #[arg(long)]
        json: bool,
    },

    /// Derive output ciphertext ID from run handle and output index
    DeriveOutput {
        /// Run handle from submit command
        #[arg(long)]
        run_handle: String,

        /// Output index (default: 0)
        #[arg(long, default_value = "0")]
        output_index: u8,
    },
}

/// Common parameters for ACL operations
#[derive(Parser, Clone)]
struct AclCommonParams {
    /// Ciphertext ID
    #[arg(long)]
    ciphertext_id: String,

    /// Address to check/grant access for
    #[arg(long)]
    address: String,

    /// Chain (web3, optional)
    #[arg(long)]
    chain: Option<NamedChain>,
}

/// Parameters specific to Run operations
#[derive(Parser, Clone)]
struct RunParams {
    /// Library
    #[arg(long)]
    library: String,

    /// Entry point (program name)
    #[arg(long)]
    entry_point: String,
}

#[derive(Subcommand)]
enum AccessCommand {
    /// Grant access permissions
    #[command(subcommand)]
    Grant(GrantCommand),

    /// Check access permissions
    #[command(subcommand)]
    Check(CheckCommand),
}

#[derive(Subcommand)]
enum GrantCommand {
    /// Grant Admin access to a ciphertext
    Admin {
        #[command(flatten)]
        common: AclCommonParams,

        /// RPC URL (web3, optional)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Wallet private key
        #[arg(long)]
        private_key: String,
    },

    /// Grant Decrypt access to a ciphertext
    Decrypt {
        #[command(flatten)]
        common: AclCommonParams,

        /// RPC URL (web3, optional)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Wallet private key
        #[arg(long)]
        private_key: String,
    },

    /// Grant Run access to a ciphertext
    Run {
        /// Ciphertext ID
        #[arg(long)]
        ciphertext_id: String,

        /// Executor address
        #[arg(long)]
        executor: String,

        /// Library ID (required in web2, omit to query contract in web3)
        #[arg(long)]
        library: Option<String>,

        /// Entry point (required in web2, omit to query contract in web3)
        #[arg(long)]
        entry_point: Option<String>,

        /// Chain (web3, optional)
        #[arg(long)]
        chain: Option<NamedChain>,

        /// RPC URL (web3, optional)
        #[arg(long)]
        rpc_url: Option<String>,

        /// Wallet private key
        #[arg(long)]
        private_key: String,
    },
}

#[derive(Subcommand)]
enum CheckCommand {
    /// Check Admin access to a ciphertext
    Admin {
        #[command(flatten)]
        common: AclCommonParams,

        /// Output full JSON response instead of just signature
        #[arg(long)]
        json: bool,
    },

    /// Check Decrypt access to a ciphertext
    Decrypt {
        #[command(flatten)]
        common: AclCommonParams,

        /// Output full JSON response instead of just signature
        #[arg(long)]
        json: bool,
    },

    /// Check Run access to a ciphertext
    Run {
        #[command(flatten)]
        common: AclCommonParams,

        #[command(flatten)]
        run_params: RunParams,

        /// Output full JSON response instead of just signature
        #[arg(long)]
        json: bool,
    },
}

/// Helper function to log chain and RPC URL debug information
fn log_chain_info(chain: Option<NamedChain>, rpc_url: Option<&str>) {
    if let Some(c) = chain {
        debug!("  Chain: {}", c);
    }
    if let Some(rpc) = rpc_url {
        debug!("  RPC URL: {}", rpc);
    }
}

/// Handle ACL check result output (JSON or simple format)
fn handle_acl_check_result(result: cli::AclCheckResult, json: bool) -> Result<()> {
    match result {
        cli::AclCheckResult::Granted {
            signature,
            message,
            access_change,
        } => {
            if json {
                let output = serde_json::json!({
                    "status": "success",
                    "payload": {
                        "signature": signature,
                        "message": message,
                        "access_change": access_change,
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!("{}", signature);
            }
            Ok(())
        }
        cli::AclCheckResult::Denied { reason } => {
            if json {
                let output = serde_json::json!({
                    "status": "failure",
                    "payload": {
                        "reason": reason,
                    }
                });
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                eprintln!("Access denied: {}", reason);
            }
            std::process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing subscriber with env filter support
    // Users can set RUST_LOG env var to control verbosity
    // Example: RUST_LOG=debug spf upload-ciphertext ...
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let args = Cli::parse();

    // Handle new-wallet command early (doesn't need public key)
    if matches!(args.command, Commands::NewWallet) {
        use alloy::signers::local::LocalSigner;

        let wallet = LocalSigner::random();
        let address = wallet.address();
        let private_key = hex::encode(wallet.credential().to_bytes());

        let output = serde_json::json!({
            "address": format!("0x{}", hex::encode(address.as_slice())),
            "privateKey": format!("0x{}", private_key),
        });

        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    // Fetch public key from endpoint
    info!("Fetching public key from SPF endpoint");
    debug!("Endpoint: {}", args.endpoint);

    let public_key_bytes = cli::fetch_public_key(&args.endpoint)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to fetch public key: {}", e))?;

    debug!("Fetched public key ({} bytes)", public_key_bytes.len());

    // Initialize client with fetched public key
    client::initialize_with_public_key(&public_key_bytes)
        .map_err(|e| anyhow::anyhow!("Client initialization failed: {}", e))?;

    info!("Client initialized successfully");

    // Use the endpoint from CLI args
    let endpoint = &args.endpoint;

    // Execute command
    match args.command {
        Commands::UploadCiphertext { file, private_key } => {
            info!("Uploading ciphertext from: {}", file);

            let signer = cli::parse_private_key(&private_key)?;
            let ciphertext_bytes = fs::read(&file)?;

            debug!("Ciphertext size: {} bytes", ciphertext_bytes.len());
            debug!(
                "First 32 bytes: {}",
                hex::encode(&ciphertext_bytes[..32.min(ciphertext_bytes.len())])
            );

            let ciphertext_id = cli::upload_ciphertext(endpoint, ciphertext_bytes, &signer).await?;

            info!("Ciphertext uploaded successfully");
            // Core output - always to stdout for scriptability
            println!("{}", ciphertext_id);
        }

        Commands::UploadProgram { file } => {
            info!("Uploading program from: {}", file);

            let program_bytes = fs::read(&file)?;

            debug!("Program size: {} bytes", program_bytes.len());

            let program_id = cli::upload_program(endpoint, program_bytes).await?;

            info!("Program uploaded successfully");
            // Core output - always to stdout for scriptability
            println!("{}", program_id);
        }

        Commands::Access(access_cmd) => match access_cmd {
            AccessCommand::Grant(grant_cmd) => match grant_cmd {
                GrantCommand::Admin {
                    common,
                    rpc_url,
                    private_key,
                } => {
                    info!(
                        "Granting Admin access for ciphertext: {}",
                        common.ciphertext_id
                    );
                    debug!("  Address: {}", common.address);
                    log_chain_info(common.chain, rpc_url.as_deref());

                    let signer = cli::parse_private_key(&private_key)?;

                    let result_id = cli::admin_access(
                        endpoint,
                        &common.ciphertext_id,
                        &common.address,
                        common.chain,
                        rpc_url.as_deref(),
                        &signer,
                    )
                    .await?;

                    info!("Admin access granted successfully");
                    println!("{}", result_id);
                }

                GrantCommand::Decrypt {
                    common,
                    rpc_url,
                    private_key,
                } => {
                    info!(
                        "Granting Decrypt access for ciphertext: {}",
                        common.ciphertext_id
                    );
                    debug!("  Address: {}", common.address);
                    log_chain_info(common.chain, rpc_url.as_deref());

                    let signer = cli::parse_private_key(&private_key)?;

                    let result_id = cli::decrypt_access(
                        endpoint,
                        &common.ciphertext_id,
                        &common.address,
                        common.chain,
                        rpc_url.as_deref(),
                        &signer,
                    )
                    .await?;

                    info!("Decrypt access granted successfully");
                    println!("{}", result_id);
                }

                GrantCommand::Run {
                    ciphertext_id,
                    executor,
                    library,
                    entry_point,
                    chain,
                    rpc_url,
                    private_key,
                } => {
                    info!("Granting Run access for ciphertext: {}", ciphertext_id);
                    debug!("  Executor: {}", executor);
                    if let Some(ref lib) = library {
                        debug!("  Library: {}", lib);
                    }
                    if let Some(ref ep) = entry_point {
                        debug!("  Entry Point: {}", ep);
                    }
                    log_chain_info(chain, rpc_url.as_deref());

                    let signer = cli::parse_private_key(&private_key)?;

                    let result_id = cli::run_access(
                        endpoint,
                        &ciphertext_id,
                        &executor,
                        library.as_deref(),
                        entry_point.as_deref(),
                        chain,
                        rpc_url.as_deref(),
                        &signer,
                    )
                    .await?;

                    info!("Run access granted successfully");
                    println!("{}", result_id);
                }
            },

            AccessCommand::Check(check_cmd) => match check_cmd {
                CheckCommand::Admin { common, json } => {
                    info!(
                        "Checking Admin access for ciphertext: {}",
                        common.ciphertext_id
                    );
                    debug!("  Address: {}", common.address);
                    if let Some(c) = common.chain {
                        debug!("  Chain: {}", c);
                    }

                    let result = cli::check_admin_access(
                        endpoint,
                        &common.ciphertext_id,
                        &common.address,
                        common.chain,
                    )
                    .await?;

                    handle_acl_check_result(result, json)?;
                }

                CheckCommand::Decrypt { common, json } => {
                    info!(
                        "Checking Decrypt access for ciphertext: {}",
                        common.ciphertext_id
                    );
                    debug!("  Address: {}", common.address);
                    if let Some(c) = common.chain {
                        debug!("  Chain: {}", c);
                    }

                    let result = cli::check_decrypt_access(
                        endpoint,
                        &common.ciphertext_id,
                        &common.address,
                        common.chain,
                    )
                    .await?;

                    handle_acl_check_result(result, json)?;
                }

                CheckCommand::Run {
                    common,
                    run_params,
                    json,
                } => {
                    info!(
                        "Checking Run access for ciphertext: {}",
                        common.ciphertext_id
                    );
                    debug!("  Address: {}", common.address);
                    debug!("  Library: {}", run_params.library);
                    debug!("  Entry Point: {}", run_params.entry_point);
                    if let Some(c) = common.chain {
                        debug!("  Chain: {}", c);
                    }

                    let result = cli::check_run_access(
                        endpoint,
                        &common.ciphertext_id,
                        &common.address,
                        &run_params.library,
                        &run_params.entry_point,
                        common.chain,
                    )
                    .await?;

                    handle_acl_check_result(result, json)?;
                }
            },
        },

        Commands::Decrypt {
            ciphertext_id,
            private_key,
            bit_width,
            sign,
        } => {
            info!("Requesting decryption for ciphertext: {}", ciphertext_id);

            let signer = cli::parse_private_key(&private_key)?;

            // Request decryption
            let decrypt_handle = cli::request_decryption(endpoint, &ciphertext_id, &signer).await?;
            debug!("Decryption handle: {}", decrypt_handle);

            // Convert sign enum to bool
            let signed = matches!(sign, Signedness::Signed);

            // Check status once (no polling)
            let client = cli::create_http_client(30)?;
            let status_url = format!("{}/decryption/{}", endpoint, decrypt_handle);
            let status_response = client.get(&status_url).send().await?;

            if !status_response.status().is_success() {
                let status = status_response.status();
                let error_text = status_response.text().await?;
                anyhow::bail!("Status check failed ({}): {}", status, error_text);
            }

            let status: serde_json::Value = status_response.json().await?;

            match status.get("status").and_then(|s| s.as_str()) {
                Some("success") => {
                    let value_array = status
                        .get("payload")
                        .and_then(|p| p.get("value"))
                        .and_then(|v| v.as_array())
                        .ok_or_else(|| anyhow::anyhow!("Missing or invalid value in payload"))?;

                    let poly_bytes: Vec<u8> = value_array
                        .iter()
                        .filter_map(|v| v.as_u64().map(|n| n as u8))
                        .collect();

                    let value = spf_client::core::crypto::parse_polynomial_to_value(
                        &poly_bytes,
                        bit_width,
                        signed,
                    )?;

                    info!("Decryption completed successfully");
                    println!("{}", value);
                }
                Some("failed") => {
                    let message = status
                        .get("payload")
                        .and_then(|p| p.get("message"))
                        .and_then(|m| m.as_str())
                        .unwrap_or("Unknown error");
                    anyhow::bail!("Decryption failed: {}", message);
                }
                Some("pending") | Some("running") | Some("in_progress") => {
                    info!("Decryption pending");
                    println!("pending");
                }
                _ => {
                    anyhow::bail!("Unknown status: {:?}", status);
                }
            }
        }

        Commands::GenerateCiphertext {
            value,
            bits,
            output,
            upload,
            private_key,
        } => {
            // Validation: ensure flag combinations are valid
            match (upload, private_key.as_ref(), output.as_ref()) {
                (true, None, _) => anyhow::bail!("Must provide --private-key when using --upload"),
                (false, Some(_), _) => anyhow::bail!("Cannot use --private-key without --upload"),
                (false, None, None) => anyhow::bail!("Must provide either --output or --upload"),
                _ => {} // Valid combinations
            }

            info!("Generating ciphertext for value: {}", value);
            debug!("Bit width: {}", bits);

            // Validate bit width
            if ![8, 16, 32, 64].contains(&bits) {
                anyhow::bail!("Invalid bit width: {}. Must be 8, 16, 32, or 64", bits);
            }

            // Determine signedness based on value
            let signed = value < 0;
            debug!(
                "Using {} encryption",
                if signed { "signed" } else { "unsigned" }
            );

            // Encrypt using native API (reuses existing functions)
            let ciphertext_bytes = if signed {
                spf_client::encrypt_signed(value, bits)?
            } else {
                spf_client::encrypt_unsigned(value as u64, bits)?
            };

            debug!("Ciphertext size: {} bytes", ciphertext_bytes.len());

            // Derive ciphertext ID for local use
            let ciphertext_id = spf_client::core::utils::derive_ciphertext_id(&ciphertext_bytes);
            debug!("Ciphertext ID: {}", ciphertext_id);

            // Upload if requested
            if upload {
                let signer = cli::parse_private_key(
                    private_key
                        .as_ref()
                        .expect("private_key validated to be Some when upload=true"),
                )?;
                info!("Uploading ciphertext to SPF service...");

                let uploaded_id =
                    cli::upload_ciphertext(endpoint, ciphertext_bytes.clone(), &signer).await?;

                info!("Ciphertext uploaded successfully");

                // Optionally write to file if output path provided
                if let Some(ref output_path) = output {
                    fs::write(output_path, &ciphertext_bytes)?;
                    debug!("Ciphertext also written to: {}", output_path);
                }

                // Core output - always to stdout for scriptability
                println!("{}", uploaded_id);
            } else {
                // Write to output file (required in non-upload mode)
                let output_path = output
                    .as_ref()
                    .expect("output validated to be Some when upload=false");
                fs::write(output_path, &ciphertext_bytes)?;
                info!("Ciphertext written to: {}", output_path);

                // Core output - always to stdout for scriptability
                println!("{}", ciphertext_id);
            }
        }

        Commands::NewWallet => {
            unreachable!("NewWallet command handled early")
        }

        Commands::Run(run_cmd) => match run_cmd {
            RunCommand::Submit {
                library,
                program,
                parameters,
                private_key,
            } => {
                info!("Submitting run for program: {}", program);
                debug!("  Library: {}", library);
                debug!("  Parameters: {}", parameters);

                let signer = cli::parse_private_key(&private_key)?;

                // Parse JSON parameters
                let param_specs: Vec<cli::RunParameterSpec> = serde_json::from_str(&parameters)
                    .map_err(|e| anyhow::anyhow!("Failed to parse parameters JSON: {}", e))?;

                debug!("  Parsed {} parameters", param_specs.len());

                // Submit run
                let run_handle =
                    cli::submit_run(endpoint, &library, &program, &param_specs, &signer).await?;

                info!("Run submitted successfully");
                println!("{}", run_handle);
            }

            RunCommand::CheckStatus { run_handle, json } => {
                info!("Checking status for run: {}", run_handle);

                let status = cli::check_run_status(endpoint, &run_handle).await?;

                if json {
                    let output = match status {
                        cli::RunStatus::Success { payload } => {
                            serde_json::json!({
                                "status": "success",
                                "payload": payload,
                            })
                        }
                        cli::RunStatus::Failed { message } => {
                            serde_json::json!({
                                "status": "failed",
                                "payload": {
                                    "message": message,
                                }
                            })
                        }
                        cli::RunStatus::Pending => {
                            serde_json::json!({
                                "status": "pending",
                            })
                        }
                    };
                    println!("{}", serde_json::to_string_pretty(&output)?);
                } else {
                    match status {
                        cli::RunStatus::Success { .. } => {
                            println!("success");
                        }
                        cli::RunStatus::Failed { message } => {
                            eprintln!("failed: {}", message);
                            std::process::exit(1);
                        }
                        cli::RunStatus::Pending => {
                            println!("pending");
                        }
                    }
                }
            }

            RunCommand::DeriveOutput {
                run_handle,
                output_index,
            } => {
                info!(
                    "Deriving output ciphertext ID from run handle: {}",
                    run_handle
                );
                debug!("Output index: {}", output_index);

                let result_id =
                    spf_client::core::utils::derive_result_id(&run_handle, output_index)?;

                info!("Output ciphertext ID derived successfully");
                println!("{}", result_id);
            }
        },
    }

    Ok(())
}
