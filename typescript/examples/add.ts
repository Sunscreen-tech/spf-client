import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import {
  initialize,
  uploadProgram,
  uploadCiphertext,
  submitRun,
  waitForRun,
  createCiphertextParameter,
  createOutputCiphertextArrayParameter,
  deriveResultCiphertextId,
  requestDecryption,
  waitForDecryption,
  encryptValue,
  PrivateKeySigner,
  asAddress,
  asProgramName,
  type AnySigner,
} from "../src/spf-client.js";
import {
  updateAccess,
  allowDecryptAccess,
  allowRunAccess,
} from "../src/acl.js";
import { TEST_ENDPOINT } from "../test/test-config.js";

export async function runAddExample(
  endpoint: string = TEST_ENDPOINT
): Promise<bigint> {
  console.log("\n=================================");
  console.log("Encrypted addition example");
  console.log("=================================\n");

  await initialize(endpoint, "test");
  console.log("Initialized SPF client\n");

  // Create two wallets: uploader and runner
  const uploader = PrivateKeySigner.random();
  const runner = PrivateKeySigner.random();

  console.log("Created wallets:");
  console.log(`  Uploader: ${uploader.getAddress()}`);
  console.log(`  Runner:   ${runner.getAddress()}\n`);

  // Upload the FHE program
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const programPath = join(__dirname, "../test/fixtures/add.spf");
  const programBytes = new Uint8Array(readFileSync(programPath));
  const libraryId = await uploadProgram(programBytes);
  console.log(`Uploaded add program: ${libraryId}\n`);

  // Encrypt and upload the values
  console.log("Encrypting values:");
  const valueA = 15;
  const valueB = 27;
  console.log(`  a = ${valueA}`);
  console.log(`  b = ${valueB}\n`);

  const ciphertextA = await encryptValue(valueA, 16);
  const ciphertextIdA = await uploadCiphertext(uploader, ciphertextA);
  console.log(`Uploaded ciphertext A: ${ciphertextIdA}`);

  const ciphertextB = await encryptValue(valueB, 16);
  const ciphertextIdB = await uploadCiphertext(uploader, ciphertextB);
  console.log(`Uploaded ciphertext B: ${ciphertextIdB}\n`);

  // Grant run access to the runner for both ciphertexts
  console.log("Granting run access to runner...");
  const newCiphertextIdA = await updateAccess(
    uploader,
    ciphertextIdA,
    [allowRunAccess(asAddress(runner.getAddress()), libraryId, asProgramName("add"))]
  );
  const newCiphertextIdB = await updateAccess(
    uploader,
    ciphertextIdB,
    [allowRunAccess(asAddress(runner.getAddress()), libraryId, asProgramName("add"))]
  );
  console.log("Run access granted\n");

  // Runner submits the computation
  console.log("Runner submitting computation...");
  const parameters = [
    createCiphertextParameter(newCiphertextIdA),
    createCiphertextParameter(newCiphertextIdB),
    createOutputCiphertextArrayParameter(16, 1),
  ];

  const runHandle = await submitRun(runner, libraryId, "add", parameters);
  console.log(`Run submitted: ${runHandle}\n`);

  console.log("Waiting for run to complete...");
  const runStatus = await waitForRun(runHandle);

  if (runStatus.status !== "success") {
    throw new Error(`Run failed: ${JSON.stringify(runStatus.payload)}`);
  }

  console.log("Run completed successfully\n");

  // Derive the result ciphertext ID
  const resultCiphertextId = deriveResultCiphertextId(runHandle, 0);
  console.log(`Result ciphertext ID: ${resultCiphertextId}\n`);

  // Grant decrypt access to uploader
  console.log("Granting decrypt access to uploader...");
  const newResultCiphertextId = await updateAccess(
    runner,
    resultCiphertextId,
    [allowDecryptAccess(asAddress(uploader.getAddress()))]
  );
  console.log("Decrypt access granted\n");

  // Uploader requests decryption
  console.log("Uploader requesting decryption...");
  const decryptHandle = await requestDecryption(uploader, newResultCiphertextId);
  console.log(`Decryption requested: ${decryptHandle}\n`);

  console.log("Waiting for decryption to complete...");
  const result = await waitForDecryption(decryptHandle, 16);
  console.log("Decryption complete\n");

  console.log("=================================");
  console.log("Result");
  console.log("=================================");
  console.log(`${valueA} + ${valueB} = ${result}`);
  console.log(`Expected: ${valueA + valueB}`);
  console.log(`Match: ${result === BigInt(valueA + valueB)}`);
  console.log("=================================\n");

  return result;
}

runAddExample()
  .then((result) => {
    console.log(`Example completed successfully. Result: ${result}`);
    process.exit(0);
  })
  .catch((error) => {
    console.error("Example failed:", error);
    process.exit(1);
  });
