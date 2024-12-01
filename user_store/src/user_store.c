#include "user_store.h" 
#include "string.h"
#include "standard_def.h"
#include "kwp.h"
#include "debug.h"
#include "gcm_api.h"

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
        array_t wrapped_key = {.buffer = new_entry->wrapped_password, .size = 24};
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


bool user_store_modify_password(struct Modify* modify)
{
    bool status = true;
    CHECK_STATUS(status, gcm_decrypt(modify->initialization_vector, NULL, 0, modify->new_password, modify->new_password, modify->password_length, modify->tag_pass, GCM_TAG_LEN));
    KW_Status_t status_kw = OK;
    array_t kek = {.buffer = user_entries.kek, .size = ARRAY_SIZE(user_entries.kek)};
    array_t wrapped_key = {.buffer = modify->new_password, .size = 24};
    array_t unwrapped_key = {.buffer = user_entries.user_entries[modify->index].wrapped_password, .size = ARRAY_SIZE(user_entries.user_entries[modify->index].wrapped_password)};

    // Zero the entry
    memset(&user_entries.user_entries[modify->index], 0, sizeof(user_entries.user_entries[modify->index]));
    KWP_VERIFY(status_kw, kw_wrap_key(&kek, &wrapped_key, &unwrapped_key));

    user_entries.user_entries[modify->index].password_length = (modify->password_length);
    memcpy(user_entries.user_entries[modify->index].info, modify->info, ARRAY_SIZE(user_entries.user_entries[modify->index].info));
    user_entries.user_entries[modify->index].isOccupied = true;

    return status;
}


bool user_store_read_entry(struct ReadEntry* read_entry, struct ReadEntryRsp* read_entry_rsp)
{
    if(NULL == read_entry || NULL == read_entry_rsp)
    {
        return false;
    }

    if (read_entry->index >= MAX_ENTRIES)
    {
        return false;
    }

    KW_Status_t status_kw = OK;
    memcpy(user_entries.kek, read_entry->kek, ARRAY_SIZE(user_entries.kek));
    array_t kek = {.buffer = user_entries.kek, .size = ARRAY_SIZE(user_entries.kek)};
    PRINT_BUFFER(read_entry->kek, 16, "KEK: ");
    array_t wrapped_key = {.buffer = user_entries.user_entries[read_entry->index].wrapped_password, .size = 32};
    array_t unwrapped_key = {.buffer = read_entry_rsp->wrapped_password, .size = ARRAY_SIZE(read_entry_rsp->wrapped_password)};

    KWP_VERIFY(status_kw, kw_unwrap_key(&kek, &wrapped_key, &unwrapped_key));
    if (status_kw != OK)
    {
        return false;
    }

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