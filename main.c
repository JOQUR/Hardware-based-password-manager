#include <stdio.h>
#include "customer_bank.h"
#include "circular_buffer.h"
#include "assert.h"
#include "test_aes.h"
#include "string.h"
#include "debug.h"
#include "ecdh.h"
#include <cbor.h>
#include "proto_bp.h"
#include "compact25519.h"


/* pseudo random number generator with 128 bit internal state... probably not suited for cryptographical usage */
typedef struct
{
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} prng_t;

static prng_t prng_ctx;

static uint32_t prng_rotate(uint32_t x, uint32_t k)
{
  return (x << k) | (x >> (32 - k)); 
}

static uint32_t prng_next(void)
{
  uint32_t e = prng_ctx.a - prng_rotate(prng_ctx.b, 27); 
  prng_ctx.a = prng_ctx.b ^ prng_rotate(prng_ctx.c, 17); 
  prng_ctx.b = prng_ctx.c + prng_ctx.d;
  prng_ctx.c = prng_ctx.d + e; 
  prng_ctx.d = e + prng_ctx.a;
  return prng_ctx.d;
}

static void prng_init(uint32_t seed)
{
  uint32_t i;
  prng_ctx.a = 0xf1ea5eed;
  prng_ctx.b = prng_ctx.c = prng_ctx.d = seed;

  for (i = 0; i < 31; ++i) 
  {
    (void) prng_next();
  }
}

void test_circular_buffer(void);
void test_circular_buffer_continous_work(void);
int test_cbor(void);
int test_protobuf(void);
void ecdh_demo(void);
void x25519_demo(void);

int main(void)
{
    test_circular_buffer();
    test_circular_buffer_continous_work();
    test_aes();
    //ecdh_test();
    //(void)test_cbor();
    (void)test_protobuf();
    ecdh_demo();
    x25519_demo();
    return 0;
}

void test_circular_buffer(void)
{
    static circular_buffer_t buffer;
    uint8_t exmaple_buffer[BUFFER_SIZE];
    uint8_t ret_buffer[BUFFER_SIZE] = {0};
    for(uint8_t i = 0; i < sizeof(exmaple_buffer); i++)
    {
        exmaple_buffer[i] = i;
    }
    assert(circular_buffer_add_array(&buffer, exmaple_buffer, sizeof(exmaple_buffer)) == OP_OK);
    assert(circular_buffer_get_array(&buffer, ret_buffer, sizeof(ret_buffer)) == OP_OK);
    assert(memcmp(ret_buffer, exmaple_buffer, sizeof(exmaple_buffer)) == 0);
    printf("%s done!\n", __func__);
}


void test_circular_buffer_continous_work(void)
{
    static circular_buffer_t buffer;
    circular_buffer_op_status status;
    uint8_t ret_buffer[6] = {0};
    for(uint8_t i = 0; i < sizeof(ret_buffer); i++)
    {
        uint8_t x;
        status = circular_buffer_add_char(&buffer, BUFFER_SIZE - i);
        assert(status == OP_OK);
        status = circular_buffer_get_char(&buffer, &x);
        assert(status == OP_OK);
        assert(x == BUFFER_SIZE - i);
    }
    printf("%s done!\n", __func__);
}

int test_cbor(void)
{
    /* Preallocate the map structure */
    cbor_item_t * root = cbor_new_definite_map(2);
    /* Add the content */
    cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_string("Is CBOR awesome?")),
        .value = cbor_move(cbor_build_bool(true))
    });
    cbor_map_add(root, (struct cbor_pair) {
        .key = cbor_move(cbor_build_uint8(42)),
        .value = cbor_move(cbor_build_string("Is the answer"))
    });
    /* Output: `buffer_size` bytes of data in the `buffer` */
    unsigned char * buffer;
    size_t buffer_size;
    cbor_serialize_alloc(root, &buffer, &buffer_size);

    fwrite(buffer, 1, buffer_size, stdout);
    free(buffer);

    fflush(stdout);
    cbor_decref(&root);
}

int test_protobuf(void)
{
    struct Shit d = {.jeden = true, .array = {1, 2, 3, 4, 5, 6, 7, 8}, .ptr = 1};
    struct Pen p = {COLOR_RED, 1611515729966, 23, d};
    unsigned char s[BYTES_LENGTH_PEN] = {0};

    // Encode p to buffer s.
    EncodePen(&p, s);

    // Decode buffer s to p1.
    struct Pen p1 = {};
    DecodePen(&p1, s);

    // Format p1 to buffer buf.
    char buf[255] = {0};
    JsonPen(&p1, buf);
    printf("%s\n", buf);

    return 0;
}

void ecdh_demo(void)
{
  static uint8_t puba[ECC_PUB_KEY_SIZE];
  static uint8_t prva[ECC_PRV_KEY_SIZE];
  static uint8_t seca[ECC_PUB_KEY_SIZE];
  static uint8_t pubb[ECC_PUB_KEY_SIZE];
  static uint8_t prvb[ECC_PRV_KEY_SIZE];
  static uint8_t secb[ECC_PUB_KEY_SIZE];
  uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
  uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

  uint32_t i;

  /* 0. Initialize and seed random number generator */
  static int initialized = 0;
  if (!initialized)
  {
    prng_init((0xbad ^ 0xc0ffee ^ 42) | 0xcafebabe | 666);
    initialized = 1;
  }

  /* 1. Alice picks a (secret) random natural number 'a', calculates P = a * g and sends P to Bob. */
  for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
  {
    prva[i] = prng_next();
  }
  assert(ecdh_generate_keys(puba, prva));

  /* 2. Bob picks a (secret) random natural number 'b', calculates Q = b * g and sends Q to Alice. */
  for (i = 0; i < ECC_PRV_KEY_SIZE; ++i)
  {
    prvb[i] = prng_next();
  }
  assert(ecdh_generate_keys(pubb, prvb));

  /* 3. Alice calculates S = a * Q = a * (b * g). */
  assert(ecdh_shared_secret(prva, pubb, seca));

  /* 4. Bob calculates T = b * P = b * (a * g). */
  assert(ecdh_shared_secret(prvb, puba, secb));

  /* 5. Assert equality, i.e. check that both parties calculated the same value. */
  for (i = 0; i < ECC_PUB_KEY_SIZE; ++i)
  {
    assert(seca[i] == secb[i]);
  }
  PRINTS("done");
}

static void generate_random_arr(uint8_t* buff, uint16_t size)
{
    for(uint16_t i = 0; i < size; i++)
    {
        buff[i] = rand() % UINT8_MAX;
    }
}

#include "AES.h"
void x25519_demo(void)
{
    PRINTS("START");

    uint8_t seed1[X25519_KEY_SIZE];
    uint8_t seed2[X25519_KEY_SIZE];
    uint8_t iv[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    uint8_t expected_out_buff[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                                     0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                                     0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                                     0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct AES_ctx ctx, ctx2;

    generate_random_arr(seed1, sizeof(seed1));
    generate_random_arr(seed2, sizeof(seed2));

    uint8_t sec1[X25519_KEY_SIZE];
    uint8_t pub1[X25519_KEY_SIZE];
    uint8_t sec2[X25519_KEY_SIZE];
    uint8_t pub2[X25519_KEY_SIZE];

    compact_x25519_keygen(sec1, pub1, seed1);
    compact_x25519_keygen(sec2, pub2, seed2);

    uint8_t shared1[X25519_SHARED_SIZE];
    uint8_t shared2[X25519_SHARED_SIZE];
    compact_x25519_shared(shared1, sec1, pub2);
    compact_x25519_shared(shared2, sec2, pub1);
    if (memcmp(shared1, shared2, X25519_SHARED_SIZE) == 0) 
    {
        PRINTS("Success");
    }
    else
    {
        PRINTS("FAIL");
    }

    AES_init_ctx_iv(&ctx, shared1, iv);
    AES_init_ctx_iv(&ctx2, shared2, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);
    AES_CBC_decrypt_buffer(&ctx2, in, 64);

    if (memcmp(in, expected_out_buff, 64) == 0) 
    {
        PRINTS("Success");
    }
    else
    {
        PRINTS("FAIL");
    }
}