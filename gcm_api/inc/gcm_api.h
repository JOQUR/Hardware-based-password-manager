/**
 * @file gcm_api.h
 * @brief Header file for GCM (Galois/Counter Mode) API.
 */

#pragma once
#include "standard_def.h"


/**
 * @def GCM_TAG_LEN
 * @brief Length of the GCM authentication tag in bytes.
 *
 * This macro defines the length of the authentication tag used in GCM mode.
 * The tag is used to ensure the integrity and authenticity of the encrypted data.
 */
#define GCM_TAG_LEN 16

/**
 * @brief Length of the Initialization Vector (IV) for Galois/Counter Mode (GCM).
 *
 * This macro defines the length of the IV used in GCM encryption and decryption.
 * The IV is a crucial component in ensuring the security of the encryption process.
 * 
 * @note The IV length for GCM is typically 12 bytes (96 bits) as recommended by NIST.
 */
#define GCM_IV_LEN 12

/**
 * @brief Initializes the GCM (Galois/Counter Mode) with the provided key.
 *
 * This function sets up the GCM context using the specified key and key size.
 *
 * @param key Pointer to the key used for GCM initialization.
 * @param keysize Size of the key in bytes.
 * @return true if initialization is successful, false otherwise.
 */
bool gcm_init(uint8_t* key, uint8_t keysize);


/**
 * @brief Encrypts the input data using Galois/Counter Mode (GCM).
 *
 * @param iv        Pointer to the initialization vector (IV).
 * @param add       Pointer to the additional authenticated data (AAD).
 * @param add_len   Length of the additional authenticated data.
 * @param input     Pointer to the input data to be encrypted.
 * @param output    Pointer to the buffer where the encrypted data will be stored.
 * @param length    Length of the input data.
 * @param tag       Pointer to the buffer where the authentication tag will be stored.
 * @param tag_len   Length of the authentication tag.
 * @return          Returns true if encryption is successful, false otherwise.
 */
bool gcm_encrypt(uint8_t* iv, uint8_t* add, uint8_t add_len, uint8_t* input, uint8_t* output, uint16_t length, uint8_t* tag, uint8_t tag_len);


/**
 * @brief Decrypts data using Galois/Counter Mode (GCM).
 *
 * This function decrypts the input data using the provided initialization vector (IV),
 * additional authenticated data (AAD), and authentication tag. The decrypted data is
 * stored in the output buffer.
 *
 * @param iv        Pointer to the initialization vector (IV).
 * @param add       Pointer to the additional authenticated data (AAD).
 * @param add_len   Length of the additional authenticated data (AAD).
 * @param input     Pointer to the input data to be decrypted.
 * @param output    Pointer to the buffer where the decrypted data will be stored.
 * @param length    Length of the input data to be decrypted.
 * @param tag       Pointer to the authentication tag.
 * @param tag_len   Length of the authentication tag.
 * 
 * @return true if decryption is successful and the authentication tag is valid, false otherwise.
 */
bool gcm_decrypt(uint8_t* iv, uint8_t* add, uint8_t add_len, uint8_t* input, uint8_t* output, uint16_t length, uint8_t* tag, uint8_t tag_len);

/**
 * @brief Deinitializes the GCM (Galois/Counter Mode) context.
 *
 * This function cleans up any resources that were allocated for the GCM context.
 * It should be called when GCM operations are no longer needed to free up resources.
 */
void gcm_deinit(void);