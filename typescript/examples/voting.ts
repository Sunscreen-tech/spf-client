import { readFileSync } from "fs";
import { join } from "path";
import {
  initialize,
  uploadProgram,
  uploadCiphertext,
  submitRun,
  waitForRun,
  createCiphertextArrayParameter,
  createPlaintextParameter,
  createOutputCiphertextArrayParameter,
  deriveResultCiphertextId,
  requestDecryption,
  waitForDecryption,
  encryptValue,
  PrivateKeySigner,
  asAddress,
} from "../src/spf-client.js";
import {
  updateAccess,
  allowDecryptAccess,
} from "../src/acl.js";
import { TEST_ENDPOINT } from "../test/test-config.js";

export async function runVotingExample(
  endpoint: string = TEST_ENDPOINT
): Promise<bigint> {
  console.log("\n=================================");
  console.log("Voting example");
  console.log("=================================\n");

  await initialize(endpoint);
  console.log("Initialized SPF client\n");

  const wallet1 = PrivateKeySigner.random();

  console.log("Created wallet:");
  console.log(`  ${wallet1.getAddress()}\n`);

  const programPath = join(__dirname, "../test/fixtures/voting.spf");
  const programBytes = new Uint8Array(readFileSync(programPath));
  const libraryId = await uploadProgram(programBytes);
  console.log(`Uploaded voting program: ${libraryId}\n`);

  const votes = [1, -1, 1, 1];

  console.log("Encrypting and uploading votes:");
  const voteCiphertextIds: string[] = [];

  for (const [index, value] of votes.entries()) {
    const ciphertext = await encryptValue(value, 8);
    const ciphertextId = await uploadCiphertext(wallet1, ciphertext);
    voteCiphertextIds.push(ciphertextId);
    console.log(`  Vote ${index + 1}: value=${value} → ${ciphertextId}`);
  }

  console.log("\nAll votes uploaded");
  console.log(`Expected: 1 + (-1) + 1 + 1 = 2 > 0 => approved\n`);

  const parameters = [
    createCiphertextArrayParameter(voteCiphertextIds),
    createPlaintextParameter(16, 4),
    createOutputCiphertextArrayParameter(8, 1),
  ];

  console.log("Submitting voting run...");
  const runHandle = await submitRun(wallet1, libraryId, "tally_votes", parameters);
  console.log(`Run submitted: ${runHandle}\n`);

  console.log("Waiting for run to complete...");
  const runStatus = await waitForRun(runHandle);

  if (runStatus.status !== "success") {
    throw new Error(`Run failed: ${JSON.stringify(runStatus.payload)}`);
  }

  console.log(`Run completed successfully`);
  if (runStatus.payload) {
    console.log(`  Gas usage: ${runStatus.payload.gas_usage}\n`);
  }

  const resultCiphertextId = deriveResultCiphertextId(runHandle, 0);
  console.log(`Result ciphertext ID: ${resultCiphertextId}\n`);

  console.log("Granting decrypt access to wallet 1...");
  await updateAccess(
    wallet1,
    resultCiphertextId,
    [allowDecryptAccess(asAddress(wallet1.getAddress()))]
  );
  console.log(`Decrypt access granted\n`);

  console.log("Requesting threshold decryption...");
  const decryptHandle = await requestDecryption(wallet1, resultCiphertextId);
  console.log(`Decryption requested: ${decryptHandle}\n`);

  console.log("Waiting for decryption to complete...");
  const result = await waitForDecryption(decryptHandle, 8);
  console.log(`Decryption complete\n`);

  console.log("=================================");
  console.log("Voting result");
  console.log("=================================");
  console.log(`Votes: [1, -1, 1, 1]`);
  console.log(`Sum: 1 + (-1) + 1 + 1 = 2`);
  console.log(`Condition: sum > 0 = ${result === 1n ? "true" : "false"}`);
  console.log(`Decrypted result: ${result}`);
  console.log(`Verdict: ${result === 1n ? "approved" : "rejected"}`);
  console.log("=================================\n");

  return result;
}

if (require.main === module) {
  runVotingExample()
    .then((result) => {
      console.log(`\nExample completed successfully. Result: ${result}`);
      process.exit(0);
    })
    .catch((error) => {
      console.error("\nExample failed:", error);
      process.exit(1);
    });
}
