#pragma once


#include "standard_def.h"

typedef enum {
    OK,
    BAD_PARAM,
    CIPHER_FAIL,
    INTEGRITY_FAIL
} KW_Status_t;


KW_Status_t kw_wrap_key(array_t* kek, array_t* unwrapped_key, array_t* wrapped_key);
KW_Status_t kw_unwrap_key(array_t* kek, array_t* wrapped_key, array_t* unwrapped_key);