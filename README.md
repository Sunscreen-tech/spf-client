# SPF Client

Client library and CLI for Sunscreen's Secure Processing Framework (SPF), enabling Fully Homomorphic Encryption (FHE) operations in web2 and web3.

## Try the Demos

**Live voting demo**: [voting-demo.sunscreen.tech](https://voting-demo.sunscreen.tech)

A complete FHE voting workflow where individual votes remain private while results are computed on encrypted data.

**Local demos**:
- `browser-demo/` - Demonstrates both web2 and web3 signing modes.
- `node-demo/` - Backend voting example

## What's Included

This repository provides four main components for working with SPF:

- Rust CLI - Command-line tool for encrypting, uploading, and managing FHE operations
- Rust Library - Core encryption library with WASM support for browser and Node.js
- TypeScript SDK - High-level client library wrapping the Rust WASM bindings
- Demos - Browser and Node.js examples showing complete workflows

## Quick Start

### Build the CLI

```sh
cargo build --release
```

The CLI binary will be available at `./target/release/spf-client`.

### Build the TypeScript Library

```sh
cd typescript
npm install
npm run build
```

This compiles both the WASM bindings and TypeScript sources.

## Usage

### CLI Example

```sh
# Generate an encrypted ciphertext and upload it to the SPF service.
spf-client generate-ciphertext \
  --value=42 \
  --bits 16 \
  --upload \
  --private-key 0x...

# Grant decrypt access to another address.
spf-client access grant decrypt \
  --ciphertext-id 0x... \
  --address 0x... \
  --private-key 0x...
```

Set `RUST_LOG=info` to enable verbose logging.

### TypeScript Example

```typescript
import { initialize, encryptValue, uploadCiphertext, PrivateKeySigner } from 'spf-client';

// Initialize the client with the SPF service.
await initialize();

// Encrypt a value client-side.
const ciphertext = await encryptValue(42, 16);

// Upload the ciphertext to SPF.
const signer = new PrivateKeySigner("0x...");
const ciphertextId = await uploadCiphertext(signer, ciphertext);
```

## Learn More

Complete documentation available at [docs.sunscreen.tech](https://docs.sunscreen.tech).

## License

MIT
