#ifndef CIRCULAR_BUFFER_H_ 
#define CIRCULAR_BUFFER_H_

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#define BUFFER_SIZE 64


typedef struct circular_buffer
{
    uint8_t data[BUFFER_SIZE];
    uint8_t head;
    uint8_t tail;
    uint8_t counter;
} circular_buffer_t;

typedef enum 
{
    OP_OK,
    OP_NOK,
    OP_BUFFER_FULL,
    OP_BUFFER_EMPTY
} circular_buffer_op_status;

circular_buffer_op_status circular_buffer_add_char(circular_buffer_t* c_buffer, uint8_t char_to_add);
circular_buffer_op_status circular_buffer_add_array(circular_buffer_t* c_buffer, uint8_t* string, size_t len);
circular_buffer_op_status circular_buffer_get_char(circular_buffer_t* c_buffer, uint8_t* char_to_read);
circular_buffer_op_status circular_buffer_get_array(circular_buffer_t* c_buffer, uint8_t* string, size_t len);

#endif