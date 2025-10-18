import * as spf from "@sunscreen/spf-client";
import { updateAccess, allowRunAccess, allowDecryptAccess } from "@sunscreen/spf-client/acl";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Generate random wallets for testing
const voters: spf.PrivateKeySigner[] = [
  spf.PrivateKeySigner.random(),
  spf.PrivateKeySigner.random(),
  spf.PrivateKeySigner.random(),
  spf.PrivateKeySigner.random(),
];
const runner: spf.PrivateKeySigner = spf.PrivateKeySigner.random();

/**
 * Encrypt a vote, upload it, and grant run access to the runner.
 * Returns the ciphertext ID with ACL applied (ready for being counted).
 */
async function encryptUploadAndGrantAccess(
  signer: spf.PrivateKeySigner,
  approve: boolean,
  runnerAddress: spf.Address,
  libraryId: spf.LibraryId,
  programName: spf.ProgramName,
): Promise<spf.CiphertextId> {
  const approveAsInt = approve ? 1 : -1;

  // Encrypt the vote
  const ciphertext = await spf.encryptValue(approveAsInt, 8);

  // Upload the ciphertext
  const uploadedId = await spf.uploadCiphertext(signer, ciphertext);

  // Grant Run access to runner (returns NEW ciphertext ID with ACL)
  const aclAppliedId = await updateAccess(signer, uploadedId, [
    allowRunAccess(runnerAddress, libraryId, programName), // runnerAddress is already Address type
  ]);

  return aclAppliedId;
}

async function tallyVotes(): Promise<number | bigint> {
  // Initialize the client
  await spf.initialize();

  // Upload program
  const programPath = join(__dirname, "../fhe-programs/compiled/voting");
  const programBytes = new Uint8Array(readFileSync(programPath));
  const libraryId = await spf.uploadProgram(programBytes);

  // Each voter encrypts, uploads, and grants Run access
  // Returns ciphertext IDs with ACL applied
  const voteValues = [true, false, true, true]; // approve, reject, approve, approve
  const voteCiphertextIds: spf.CiphertextId[] = [];

  for (let i = 0; i < voters.length; i++) {
    const voter = voters[i];
    const voteValue = voteValues[i];
    if (voter === undefined || voteValue === undefined) {
      throw new Error(`Missing voter or vote at index ${i}`);
    }

    const aclAppliedId = await encryptUploadAndGrantAccess(
      voter,
      voteValue,
      spf.asAddress(runner.getAddress()),
      libraryId,
      spf.asProgramName("tally_votes"),
    );

    voteCiphertextIds.push(aclAppliedId);
  }

  // Runner submits run using the ACL-applied ciphertext IDs
  const parametersWithAuth: spf.SpfParameterWithAuth[] = [
    spf.createCiphertextArrayParameter(voteCiphertextIds),
    spf.createPlaintextParameter(16, 4), // num_votes as uint16
    spf.createOutputCiphertextArrayParameter(8, 1), // bool output
  ];

  const runHandle = await spf.submitRun(
    runner,
    libraryId,
    spf.asProgramName("tally_votes"),
    parametersWithAuth,
  );
  console.log("Run submitted:", runHandle);

  // Wait for completion
  const runStatus = await spf.waitForRun(runHandle);
  console.log("Run status:", runStatus.status);

  // Verify the run succeeded
  if (runStatus.status !== "success") {
    throw new Error(`Run failed: ${JSON.stringify(runStatus.payload)}`);
  }

  // Get result ciphertext ID
  const resultId = spf.deriveResultCiphertextId(runHandle, 0);
  console.log("Result ciphertext ID:", resultId);

  // Runner grants itself decrypt access (runner is already admin of result)
  await updateAccess(runner, resultId, [
    allowDecryptAccess(spf.asAddress(runner.getAddress())),
  ]);
  console.log("Decrypt access granted");

  // Decrypt result (8-bit unsigned boolean value)
  const decryptHandle = await spf.requestDecryption(runner, resultId);
  console.log("Decryption requested:", decryptHandle);

  const plaintext = await spf.waitForDecryption(decryptHandle, 8, false);
  console.log("Decrypted plaintext:", plaintext);

  console.log("Voting Result:", plaintext === 1n ? "Approved" : "Rejected");

  return plaintext;
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  tallyVotes().catch(console.error);
}

export { tallyVotes };
