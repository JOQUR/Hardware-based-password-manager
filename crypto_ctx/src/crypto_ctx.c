#include "crypto_ctx.h"
#include "string.h"
#include "assert.h"
#include "compact25519.h"
#include "stdlib.h"
#include "AES.h"
#include "debug.h"

typedef struct CryptoCtx
{
    bool isInitialized;
    uint8_t* shared_secret;
    uint8_t* server_private_key;
    uint8_t* server_public_key;
    uint8_t* client_public_key;
    uint8_t* key_mask;
    uint8_t* seed;
    uint8_t* iv;
} CryptoCtx_t;

static CryptoCtx_t CryptoContext;
static struct AES_ctx aes_ctx;


static bool cryptoctx_generate_seed(void);
static bool cryptoctx_generate_iv(void);

bool cryptoctx_init(void)
{
    bool status = true;
    if(CryptoContext.isInitialized)
    {
        cryptoctx_deinit();
    }
    memset(&CryptoContext, 0x00, sizeof(CryptoCtx_t));
    CryptoContext.isInitialized = true;
    CHECK_STATUS(status, cryptoctx_generate_seed());
    CHECK_STATUS(status, cryptoctx_generate_key_pair());
    CHECK_STATUS(status, cryptoctx_generate_iv());
    return status;
}


void cryptoctx_deinit(void)
{
    // Add writing random data into allocated buffers inside struct and then free all of them
    memset(&CryptoContext, 0x00, sizeof(CryptoCtx_t));
}


void cryptoctx_generate_rand_byte(uint8_t* byte)
{
    *byte = (uint8_t)(rand() % UINT8_MAX);
}

void cryptoctx_generate_rand_buffer(uint8_t* buffer, size_t buffer_size)
{
    for (size_t i = 0; i < buffer_size; i++)
    {
        cryptoctx_generate_rand_byte(buffer++);
    }
}


bool cryptoctx_set_client_public_key(uint8_t* pub_key)
{
    bool status = true;
    uint8_t* public_key = NULL;
    if(CryptoContext.isInitialized && (NULL == CryptoContext.client_public_key))
    {
        public_key = malloc(X25519_KEY_SIZE);
    }
    else
    {
        status &= false;
    }

    if((NULL != public_key) && (true == status))
    {
        memcpy(public_key, pub_key, X25519_KEY_SIZE);
        CryptoContext.client_public_key = public_key;
    }
    else
    {
        status &= false;
    }   

    return status;
}

bool cryptoctx_get_server_public_key(uint8_t* buffer)
{
    bool status = true;
    if(CryptoContext.isInitialized && (NULL != CryptoContext.server_public_key))
    {
        memcpy(buffer, CryptoContext.server_public_key, X25519_KEY_SIZE);
    }
    else 
    {
        status &= false;
    }

    return status;
}


bool cryptoctx_generate_key_pair(void)
{
    bool status = true;
    uint8_t* private_key = NULL;
    uint8_t* server_public_key = NULL;
    private_key = malloc(X25519_KEY_SIZE);
    server_public_key = malloc(X25519_KEY_SIZE);
    if ((NULL != private_key) && (NULL != server_public_key))
    {
        CryptoContext.server_private_key = private_key;
        CryptoContext.server_public_key = server_public_key;
        compact_x25519_keygen(CryptoContext.server_private_key, CryptoContext.server_public_key, CryptoContext.seed);
    }
    else
    {
        status &= false;
    }

    return status;
}

bool cryptoctx_generate_shared_secret(void)
{
    bool status = true;
    uint8_t* shared_secet = NULL;
    shared_secet = malloc(X25519_SHARED_SIZE);
    if(NULL != shared_secet)
    {
        CryptoContext.shared_secret = shared_secet;
    }
    else
    {
        status &= false;
    }

    if(CryptoContext.isInitialized == true)
    {
        compact_x25519_shared(CryptoContext.shared_secret, CryptoContext.server_private_key, CryptoContext.client_public_key);
    }
    else
    {
        status &= false;
    }

    return status;
}

void cryptoctx_prepare_aes(void)
{
    AES_init_ctx_iv(&aes_ctx, CryptoContext.shared_secret, CryptoContext.iv);
}

bool cryptoctx_encrypt(uint8_t* data, uint16_t len)
{
    PRINT_BUFFER(data, len, "DATA: ");
    AES_CBC_encrypt_buffer(&aes_ctx, data, len);
    PRINT_BUFFER(data, len, "ENCRYPTED: ");
    PRINT_BUFFER(CryptoContext.shared_secret, 32, "SHARED SECRET: ");
    PRINT_BUFFER(CryptoContext.iv, 16, "IV: ");
}
static bool cryptoctx_generate_seed(void)
{
    bool status = true;
    uint8_t* seed = malloc(X25519_KEY_SIZE);
    if(NULL != seed)
    {
        cryptoctx_generate_rand_buffer(seed, X25519_KEY_SIZE);
        CryptoContext.seed = seed;
    }
    else
    {
        status &= false;
    }
    return status;
}

static bool cryptoctx_generate_iv(void)
{
    bool status = true;

    uint8_t* iv = NULL;
    iv = malloc(AES_BLOCKLEN);

    if(NULL != iv)
    {
        cryptoctx_generate_rand_buffer(iv, AES_BLOCKLEN);
        CryptoContext.iv = iv;
    }
    else
    {
        status &= false;
    }

    return status;
}

uint8_t* cryptoctx_get_iv(void)
{
    return CryptoContext.iv;
}

