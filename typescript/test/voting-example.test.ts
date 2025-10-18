import { describe, it, expect } from "vitest";
import { runVotingExample } from "../examples/voting.js";
import { TEST_ENDPOINT } from "./test-config.js";

describe("Voting Example", () => {
  it(
    "should complete voting workflow with ACL grants",
    async () => {
      // This test validates that the example runs through all steps
      // including vote encryption, ACL grants, run submission, and decryption
      const result = await runVotingExample(TEST_ENDPOINT);

      // Verify the result is the expected voting outcome
      // Votes [1, -1, 1, 1] sum to 2, which is > 0, so result should be 1 (approved)
      expect(result).toBe(1n);
    },
    {
      timeout: 120000, // 2 minutes for full workflow
    },
  );
});
