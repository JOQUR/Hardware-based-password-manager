#include "user_store.h" 
#include "string.h"
#include "standard_def.h"
#include "kwp.h"
#include "debug.h"


#define ALL_ENTRIES_ARE_OCCUPIED 0xFFFF
#define MAX_ENTRIES 32
typedef struct entries
{
    user_entry_t user_entries[MAX_ENTRIES];
    uint8_t index;
    uint8_t kek[16];
} entries_t;

static entries_t user_entries;
static uint16_t user_store_find_empty_entry(void);

bool user_store_add_new_entry(struct AddEntry* new_entry, uint8_t* index)
{
    if(NULL == new_entry || NULL == index)
    {
        return false;
    }

    bool status = true;
    uint16_t idx = user_store_find_empty_entry();
    KW_Status_t status_kw = OK;
    
    if (idx == ALL_ENTRIES_ARE_OCCUPIED)
    {
        status &= false;
    }
    else
    {
        *index = idx;
        user_entries.user_entries[idx].password_length = (new_entry->password_length);
        array_t kek = {.buffer = new_entry->kek, .size = ARRAY_SIZE(new_entry->kek)};
        array_t wrapped_key = {.buffer = new_entry->wrapped_password, .size = ARRAY_SIZE(new_entry->wrapped_password)};
        array_t unwrapped_key = {.buffer = user_entries.user_entries[idx].wrapped_password, .size = ARRAY_SIZE(user_entries.user_entries[idx].wrapped_password)};

        KWP_VERIFY(status_kw, kw_wrap_key(&kek, &wrapped_key, &unwrapped_key));

        if(status_kw != OK)
        {
            return false;
        }

        memcpy(user_entries.user_entries[idx].wrapped_password, unwrapped_key.buffer, ARRAY_SIZE(user_entries.user_entries[idx].wrapped_password));
        memcpy(user_entries.user_entries[idx].info, new_entry->info, ARRAY_SIZE(user_entries.user_entries[idx].info));
        memcpy(user_entries.kek, new_entry->kek, ARRAY_SIZE(user_entries.kek));
        user_entries.user_entries[idx].isOccupied = true;
    }


    return status;
}

bool user_store_del_entry(uint8_t index)
{
    if (index >= MAX_ENTRIES)
    {
        return false;
    }

    memset(&user_entries.user_entries[index], 0, sizeof(user_entries.user_entries[index]));
    return true;
}



static uint16_t user_store_find_empty_entry(void)
{
    for (uint8_t i = 0; i < MAX_ENTRIES; i++)
    {
        if (false == user_entries.user_entries[i].isOccupied)
        {
            return i;
        }
    }
    return ALL_ENTRIES_ARE_OCCUPIED;
}