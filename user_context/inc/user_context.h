#pragma once
#include "standard_def.h"

// Chyba tworzenie userow bez sensu, wystarczy jeden, ale trzeba utworzyć itp

typedef struct usr_ctx {
    bool isLogged;
    uint8_t login[32];
    uint8_t pass_hash[32];
} user_ctx_t;

typedef struct storage {
    uint8_t info[64];
    uint8_t password[64];
    uint8_t pass_len;
} storage_t;


bool user_ctx_init(uint8_t* login, uint8_t* pass_hash);
bool user_ctx_verify_user(uint8_t* login, uint8_t* pass_hash);
