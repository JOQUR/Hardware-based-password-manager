#include "kwp.h"
#include "AES.h"
#include "string.h"

#define ICV 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6
#define IV_LEN 8


KW_Status_t kw_wrap_key(array_t* kek, array_t* unwrapped_key, array_t* wrapped_key)
{
    KW_Status_t status = OK;
    uint8_t iv[IV_LEN] = {ICV};
    int i, j, k;                                /* Loop counters            */
    unsigned int n;                             /* Number of 64-bit blocks  */
    unsigned int t, tt;                         /* Step counters            */
    unsigned char *A;                           /* Integrity check register */
    uint8_t B[16];                        /* Buffer for encryption    */
    unsigned char *R;                           /* Pointer to register i    */
    struct AES_ctx aes_ctx;                     /* AES context              */

    AES_init_ctx(&aes_ctx, kek->buffer);

    /*
     * Ensure the plaintext length is valid (Note: "& 0x07" == "% 8")
     */
    if ((unwrapped_key->size & 0x07) || (!unwrapped_key->size))
    {
        return BAD_PARAM;
    }

    /*
     * Determine the number of 64-bit blocks to process
     */
    n = unwrapped_key->size >> 3;

    /*
     * Assign the IV
     */
    A = B;
    
    memcpy(A, iv, IV_LEN);
    /*
     * Perform the key wrap
     */
    memcpy(wrapped_key->buffer + 8, unwrapped_key->buffer, unwrapped_key->size);
    for (j = 0, t = 1; j <= 5; j++)
    {
        for (i = 1, R = wrapped_key->buffer + 8; i <= n; i++, t++, R += 8)
        {
            memcpy(B + 8, R, 8);
            AES_ECB_encrypt(&aes_ctx, B);
            for (k = 7, tt = t; (k >= 0) && (tt > 0); k--, tt >>= 8)
            {
                A[k] ^= (unsigned char) (tt & 0xFF);
            }
            memcpy(R, B+8, 8);
        }
    }
    memcpy(wrapped_key->buffer, A, 8);

    /*
     * Set the ciphertext length value
     */
    wrapped_key->size = unwrapped_key->size + 8;

    return status;
}

KW_Status_t kw_unwrap_key(array_t* kek, array_t* wrapped_key, array_t* unwrapped_key)
{
    KW_Status_t status = OK;
    uint8_t iv[IV_LEN] = {ICV};
    int i, j, k;                                /* Loop counters            */
    unsigned int n;                             /* Number of 64-bit blocks  */
    unsigned int t, tt;                         /* Step counters            */
    unsigned char *A;                           /* Integrity check register */
    unsigned char B[16];                        /* Buffer for encryption    */
    unsigned char *R;                           /* Pointer to register i    */
    struct AES_ctx aes_ctx;                     /* AES context              */

    AES_init_ctx(&aes_ctx, kek->buffer);
    /*
     * Ensure the plaintext length is valid (Note: "& 0x07" == "% 8")
     */
    if ((wrapped_key->size & 0x07) || (!wrapped_key->size))
    {
        return BAD_PARAM;
    }

    /*
     * Determine the number of 64-bit blocks to process
     */
    n = (wrapped_key->size-8) >> 3;

    /*
     * Assign A to be C[0] (first 64-bit block of the ciphertext)
     */
    A = B;
    memcpy(A, wrapped_key->buffer, 8);

    /*
     * Perform the key wrap
     */
    memcpy(unwrapped_key->buffer, wrapped_key->buffer + 8, wrapped_key->size - 8);
    for (j = 5, t = 6 * n; j >= 0; j--)
    {
        for (i = n, R = unwrapped_key->buffer + wrapped_key->size - 16;
             i >= 1;
             i--, t--, R -= 8)
        {
            for (k = 7, tt = t; (k >= 0) && (tt > 0); k--, tt >>= 8)
            {
                A[k] ^= (unsigned char) (tt & 0xFF);
            }
            memcpy(B + 8, R, 8);
            AES_ECB_decrypt(&aes_ctx, B);
            memcpy(R, B + 8, 8);
        }
    }

    /*
     * Set the ciphertext length value
     */


    unwrapped_key->size = wrapped_key->size - 8;
    if (memcmp(iv, A, 8))
    {
        status |= INTEGRITY_FAIL;
    }

    return status;
}