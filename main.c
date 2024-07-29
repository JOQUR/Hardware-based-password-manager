#include <stdio.h>
#include "customer_bank.h"
#include "circular_buffer.h"
#include "assert.h"
#include "test_aes.h"
#include "string.h"
#include "debug.h"
#include "test_ecdh.h"
#include <cbor.h>

void test_circular_buffer(void);
void test_circular_buffer_continous_work(void);
int test_cbor();

int main(void)
{
    test_circular_buffer();
    test_circular_buffer_continous_work();
    test_aes();
    ecdh_test();
    (void)test_cbor();
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

int test_cbor()
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
