#include "circular_buffer.h"
#include "assert.h"
#include "debug.h"


static bool circular_buffer_is_full(circular_buffer_t* c_buffer);
static bool circular_buffer_is_empty(circular_buffer_t* c_buffer);


circular_buffer_op_status circular_buffer_add_char(circular_buffer_t* c_buffer, uint8_t char_to_add)
{
    assert(NULL != c_buffer);
    if(circular_buffer_is_full(c_buffer))
    {
        return OP_BUFFER_FULL;
    }
    PRINT(char_to_add);
    c_buffer->data[c_buffer->head] = char_to_add;
    c_buffer->head = (c_buffer->head + 1) % BUFFER_SIZE;
    c_buffer->counter++;
    return OP_OK;
}
circular_buffer_op_status circular_buffer_add_array(circular_buffer_t* c_buffer, uint8_t* string, size_t len)
{
    assert(NULL != c_buffer);    
    assert((NULL != string) && (len > 0));

    circular_buffer_op_status status = OP_OK;

    for(size_t i = 0; i < len; i++)
    {
        status = circular_buffer_add_char(c_buffer, string[i]);
        if(status != OP_OK)
        {
            return status;
        }
    }
    return status;

}
circular_buffer_op_status circular_buffer_get_char(circular_buffer_t* c_buffer, uint8_t* char_to_read)
{
    assert(NULL != c_buffer);
    assert(NULL != char_to_read);
    
    if(circular_buffer_is_empty(c_buffer))
    {
        return OP_BUFFER_EMPTY;
    }

    *char_to_read = c_buffer->data[c_buffer->tail];
    PRINT(*char_to_read);
    c_buffer->tail = (c_buffer->tail + 1) % BUFFER_SIZE;
    c_buffer->counter--;
    return OP_OK;
}
circular_buffer_op_status circular_buffer_get_array(circular_buffer_t* c_buffer, uint8_t* string, size_t len)
{
    assert(NULL != c_buffer);
    assert((NULL != string) && (len > 0));

    circular_buffer_op_status status = OP_OK;

    for(size_t i = 0; i < len; i++)
    {
        uint8_t temp_char;
        status = circular_buffer_get_char(c_buffer, &temp_char);
        if(status != OP_OK)
        {
            return status;
        }
        string[i] = temp_char;
        PRINT(temp_char);
    }
    return status;
}

static bool circular_buffer_is_full(circular_buffer_t* c_buffer)
{
    if((BUFFER_SIZE == c_buffer->counter) && (c_buffer->head == c_buffer->tail))
    {
        return true;
    }
    else
        return false;
}
static bool circular_buffer_is_empty(circular_buffer_t* c_buffer)
{
    if((0 == c_buffer->counter) && (c_buffer->head == c_buffer->tail))
    {
        return true;
    }
    else
        return false;
}
