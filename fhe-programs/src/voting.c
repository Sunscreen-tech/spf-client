#include <parasol.h>

/**
 * Performs encrypted voting on a single issue.
 *
 * Tallies encrypted votes where voters approve or reject an issue. The issue
 * passes if the sum of all votes is greater than 0.
 *
 * @param[in] votes Array of encrypted votes (each vote should be +1 or -1).
 * @param[in] num_votes Total number of votes in the array.
 * @param[out] didTheIssuePass Encrypted boolean indicating if the issue passed.
 *
 * @note The [[clang::fhe_program]] attribute marks this as an FHE program.
 * @note The [[clang::encrypted]] attribute indicates parameters that are passed
 *       in as encrypted values.
 */
[[clang::fhe_program]]
void tally_votes([[clang::encrypted]] int8_t *votes,
                 uint16_t num_votes,
                 [[clang::encrypted]] bool *didTheIssuePass) {
  int16_t sum = 0;

  for (uint16_t i = 0; i < num_votes; i++) {
    // Use iselect8 to sanitize votes: keep the vote if it is -1 or 1, otherwise
    // set the vote to 0.
    int8_t sanitized_vote =
        iselect8(votes[i] == 1 || votes[i] == -1, votes[i], 0);
    sum += sanitized_vote;
  }

  // The issue passes if more people voted in favor of the issue.
  *didTheIssuePass = sum > 0;
}
