#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#pragma once

typedef struct array
{
    uint8_t* buffer;
    uint16_t size;
} array_t;

#define ARRAY_CMP(_ARR1_, _ARR2_, _ARR_SIZE_)       (0 == memcmp(_ARR1_, _ARR2_, _ARR_SIZE_))
#define ARRAY_VALIDATION(__ARR__)                   ((((__ARR__)->buffer) != NULL) && ((__ARR__)->size != 0))
#define ARRAY_SIZE(__ARR__)                         (sizeof((__ARR__)) / sizeof((__ARR__)[0]))

#define CHECK_STATUS(_STATUS_, _OP_)                if (_STATUS_ == true) { _STATUS_ &= _OP_; }