#include "gcm_api.h"
#include "gcm.h"

static gcm_context ctx;

bool gcm_init(uint8_t* key, uint8_t keysize)
{
    int ret = 0;
    ret |= gcm_initialize();
    ret |= gcm_setkey(&ctx, key, keysize);
    return (ret == 0);
}

bool gcm_encrypt(uint8_t* iv, uint8_t* add, uint8_t add_len, uint8_t* input, uint8_t* output, uint16_t length, uint8_t* tag, uint8_t tag_len)
{
    int ret = 0;
    ret |= gcm_crypt_and_tag(&ctx, ENCRYPT, iv, GCM_IV_LEN, add, add_len, input, output, length, tag, GCM_TAG_LEN);
    return (ret == 0);
}

bool gcm_decrypt(uint8_t* iv, uint8_t* add, uint8_t add_len, uint8_t* input, uint8_t* output, uint16_t length, uint8_t* tag, uint8_t tag_len)
{
    int ret = 0;
    ret |= gcm_auth_decrypt(&ctx, iv, GCM_IV_LEN, add, add_len, input, output, length, tag, GCM_TAG_LEN);
    return (ret == 0);
}


void gcm_deinit(void)
{
    gcm_zero_ctx(&ctx);
}