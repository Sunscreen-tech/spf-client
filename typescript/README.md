# @sunscreen/spf-client

TypeScript client library for Sunscreen's Secure Processing Framework (SPF), enabling Fully Homomorphic Encryption (FHE) operations in web2 and web3 environments.

## Installation

```bash
npm install @sunscreen/spf-client
```

## Example: Encrypted Addition

This example demonstrates encrypting two values, running an FHE program to add them, and decrypting the result.

### FHE Program

FHE programs are written in C and compiled with the Sunscreen LLVM compiler from [github.com/Sunscreen-tech/sunscreen-llvm](https://github.com/Sunscreen-tech/sunscreen-llvm).

```c
#include <parasol.h>

[[clang::fhe_program]]
void add([[clang::encrypted]] int16_t a,
         [[clang::encrypted]] int16_t b,
         [[clang::encrypted]] int16_t *result) {
  *result = a + b;
}
```

### TypeScript Client

```typescript
import * as spf from '@sunscreen/spf-client';
import * as acl from '@sunscreen/spf-client/acl';

// Initialize the client
await spf.initialize();

// Create wallets for uploader and runner
const uploader = spf.PrivateKeySigner.random();
const runner = spf.PrivateKeySigner.random();

// Upload the compiled FHE program
const programBytes = new Uint8Array(readFileSync("add.spf"));
const libraryId = await spf.uploadProgram(programBytes);

// Encrypt and upload values
const ciphertextA = await spf.encryptValue(15, 16);
const ciphertextIdA = await spf.uploadCiphertext(uploader, ciphertextA);

const ciphertextB = await spf.encryptValue(27, 16);
const ciphertextIdB = await spf.uploadCiphertext(uploader, ciphertextB);

// Grant run access to runner (returns new ciphertext IDs)
const newCiphertextIdA = await acl.updateAccess(uploader, ciphertextIdA, [
  acl.allowRunAccess(spf.asAddress(runner.getAddress()), libraryId, spf.asProgramName("add"))
]);
const newCiphertextIdB = await acl.updateAccess(uploader, ciphertextIdB, [
  acl.allowRunAccess(spf.asAddress(runner.getAddress()), libraryId, spf.asProgramName("add"))
]);

// Runner submits the computation
const parameters = [
  spf.createCiphertextParameter(newCiphertextIdA),
  spf.createCiphertextParameter(newCiphertextIdB),
  spf.createOutputCiphertextArrayParameter(16, 1),
];
const runHandle = await spf.submitRun(runner, libraryId, "add", parameters);

// Wait for computation to complete
await spf.waitForRun(runHandle);

// Derive result ciphertext ID
const resultCiphertextId = spf.deriveResultCiphertextId(runHandle, 0);

// Grant decrypt access to uploader (returns new ciphertext ID)
const newResultCiphertextId = await acl.updateAccess(runner, resultCiphertextId, [
  acl.allowDecryptAccess(spf.asAddress(uploader.getAddress()))
]);

// Uploader requests decryption
const decryptHandle = await spf.requestDecryption(uploader, newResultCiphertextId);
const result = await spf.waitForDecryption(decryptHandle, 16);

console.log(`15 + 27 = ${result}`); // Output: 15 + 27 = 42
```

## Documentation

Complete documentation is available at [spf-docs.sunscreen.tech](https://spf-docs.sunscreen.tech).

## License

MIT
