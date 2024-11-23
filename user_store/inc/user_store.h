#ifndef USER_STORE_H_ 
#define USER_STORE_H_

#include <stdio.h>
#include <stdint.h>
#include "messaging_bp.h"


typedef struct user_entry
{
    uint8_t info[32];
    uint8_t wrapped_password[32];
    uint8_t password_length;
} user_entry_t;


bool user_store_add_new_entry(struct AddEntry* new_entry);

#endif