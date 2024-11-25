#pragma once


#include "standard_def.h"

/**
 * @brief Enumeration for key wrapping purposes.
 */
typedef enum {
    OK,
    BAD_PARAM,
    CIPHER_FAIL,
    INTEGRITY_FAIL
} KW_Status_t;

#define KWP_VERIFY(__STATUS__, __OP__)  if(__STATUS__ == OK) {__STATUS__ |= __OP__;};

/**
 * @brief Wraps a key using a Key Encryption Key (KEK).
 *
 * This function wraps an unwrapped key using the provided Key Encryption Key (KEK)
 * and stores the result in the wrapped_key array.
 *
 * @param[in] kek Pointer to the array containing the Key Encryption Key (KEK).
 * @param[in] unwrapped_key Pointer to the array containing the key to be wrapped.
 * @param[out] wrapped_key Pointer to the array where the wrapped key will be stored.
 *
 * @return KW_Status_t Status code indicating the success or failure of the key wrapping operation.
 */
KW_Status_t kw_wrap_key(array_t* kek, array_t* unwrapped_key, array_t* wrapped_key);

/**
 * @brief Unwraps a wrapped key using a key encryption key (KEK).
 *
 * This function takes a wrapped key and a key encryption key (KEK) and
 * unwraps the wrapped key to produce the original unwrapped key.
 *
 * @param[in] kek Pointer to an array_t structure containing the key encryption key.
 * @param[in] wrapped_key Pointer to an array_t structure containing the wrapped key.
 * @param[out] unwrapped_key Pointer to an array_t structure where the unwrapped key will be stored.
 * @return KW_Status_t Status code indicating the result of the unwrapping operation.
 */
KW_Status_t kw_unwrap_key(array_t* kek, array_t* wrapped_key, array_t* unwrapped_key);