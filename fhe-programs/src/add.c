#include <parasol.h>

/**
 * Performs encrypted addition of two values.
 *
 * Adds two encrypted signed 16-bit integers and returns the encrypted result.
 *
 * @param[in] a First encrypted value to add
 * @param[in] b Second encrypted value to add
 * @param[out] result Encrypted sum of a and b
 *
 * @note The [[clang::fhe_program]] attribute marks this as an FHE program.
 * @note The [[clang::encrypted]] attribute indicates parameters that are passed
 *       in as encrypted values.
 */
[[clang::fhe_program]]
void add([[clang::encrypted]] int16_t a,
         [[clang::encrypted]] int16_t b,
         [[clang::encrypted]] int16_t *result) {
  *result = a + b;
}
