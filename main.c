#include <stdio.h>
#include "customer_bank.h"
#include "circular_buffer.h"
#include "assert.h"
#include "aes_crypto.h"
#include "string.h"
#include "debug.h"

void test_circular_buffer(void);
void test_circular_buffer_continous_work(void);

int main(void)
{
    test_circular_buffer();
    test_circular_buffer_continous_work();
    aes_crypto();
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