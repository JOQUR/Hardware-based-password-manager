#include "user_store.h" 
#include "string.h"
#include "standard_def.h"
typedef struct entries
{
    user_entry_t user_entries[32];
    uint8_t index;
} entries_t;


static entries_t user_entries;


bool user_store_add_new_entry(struct AddEntry* new_entry)
{
    bool status = true;
    uint8_t idx = user_entries.index;
    if (user_entries.index >= ARRAY_SIZE(user_entries.user_entries))
    {
        status &= false;
    }
    else
    {
        user_entries.user_entries[idx].password_length = (new_entry->password_length);
        memcpy(user_entries.user_entries[idx].wrapped_password, new_entry->wrapped_password, ARRAY_SIZE(user_entries.user_entries[idx].wrapped_password));
        memcpy(user_entries.user_entries[idx].info, new_entry->info, ARRAY_SIZE(user_entries.user_entries[idx].info));
        user_entries.index++;
    }


    return status;
}
