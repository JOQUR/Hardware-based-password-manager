#include "app.h"
#include "debug.h"
#include "crypto_ctx.h"
#include "user_context.h"
#include "user_store.h"
#include <string.h>
#include "gcm_api.h"

static bool app_generate_password(bool generate, struct GenerateRsp* generate_rsp);
static bool app_process_new_entry(struct AddEntry* new_entry, struct AddEntryRsp* new_entry_rsp);
static bool app_del_entry(uint8_t index);
static bool app_modify_entry(struct Modify* modify, struct ModifyRsp* modify_rsp);
static bool app_read_entry(struct ReadEntry* read_entry, struct ReadEntryRsp* read_entry_rsp);

extern bool messenger_process_message(array_t* message, array_t* response, bool* send_reponse);
extern message_processor processor_cbk;

bool app_process_message(array_t* message, array_t* response, bool* send_reponse)
{
    bool status = true;
    CHECK_STATUS(status, !((NULL == message) || (NULL == response)));
    CHECK_STATUS(status, status &= (0 != message->size));
    struct App app_message = {0};
    struct AppRsp app_reponse = {0};

    if (status)
    {

        DecodeApp(&app_message, message->buffer);

        switch (app_message.node_id)
        {
            case ADD_ENTRY:
            {
                status &= app_process_new_entry(&app_message.new_entry, &app_reponse.new_entry);
                app_reponse.node_id = ADD_ENTRY;
                *send_reponse = true;
            }
            break;

            case GENERATE:
            {
                status &= app_generate_password(app_message.generate.generate, &(app_reponse.generate));
                app_reponse.node_id = GENERATE;
                *send_reponse = true;
            }
            break;

            case DEL_ENTRY:
            {
                status &= app_del_entry(app_message.del_entry.index);
                app_reponse.node_id = DEL_ENTRY;
                app_reponse.del_entry.ack = status;
                *send_reponse = true;
            }
            break;

            case MODIFY:
            {
                status &= app_modify_entry(&app_message.modify, &app_reponse.modify);
                app_reponse.node_id = MODIFY;
                *send_reponse = true;
            }
            break;

            case READ_ENTRY:
            {
                status &= app_read_entry(&app_message.read, &app_reponse.read);
                app_reponse.node_id = READ_ENTRY;
                *send_reponse = true;
            }
            break;

            default:
            {
                status &= false;
                *send_reponse = false;
            }
            break;
        }
    }
    else
    {
        // Nothing
    }
    response->size = sizeof(struct AppRsp);
    EncodeAppRsp(&app_reponse, response->buffer);
    return status;
}


static bool app_process_new_entry(struct AddEntry* new_entry, struct AddEntryRsp* new_entry_rsp)
{
    bool status = true;

    // Now decrypt Kek and password
    CHECK_STATUS(status, gcm_decrypt(new_entry->initialization_vector, NULL, 0, new_entry->kek, new_entry->kek, 16, new_entry->tag_kek, GCM_TAG_LEN));
    CHECK_STATUS(status, gcm_decrypt(new_entry->initialization_vector, NULL, 0, new_entry->wrapped_password, new_entry->wrapped_password, new_entry->password_length, new_entry->tag_pass, GCM_TAG_LEN));
    PRINT_BUFFER(new_entry->kek, sizeof(new_entry->kek), "KEK");
    CHECK_STATUS(status, user_store_add_new_entry(new_entry, &new_entry_rsp->index));

    if (status)
    {
        memcpy(new_entry_rsp->info, new_entry->info, sizeof(new_entry_rsp->info));
    }

    PRINTS(new_entry->wrapped_password);

    return status;
} 

static bool app_generate_password(bool generate, struct GenerateRsp* generate_rsp)
{
    bool status = true;

    if (true == generate)
    {
        uint8_t generated_password[32] = {0};
        cryptoctx_generate_rand_buffer(generated_password, sizeof(generated_password));
        PRINT_BUFFER(generated_password, sizeof(generated_password), "Generated Password");
        cryptoctx_generate_iv();
        memcpy(generate_rsp->initialization_vector, cryptoctx_get_iv(), GCM_IV_LEN);
        gcm_encrypt(generate_rsp->initialization_vector, NULL, 0, generated_password, generate_rsp->generated_password, sizeof(generate_rsp->generated_password), generate_rsp->tag, sizeof(generate_rsp->tag));
    }
    else
    {
        status = false;
    }

    return status;
}

static bool app_del_entry(uint8_t index)
{
    bool status = true;
    status &= user_store_del_entry(index);
    return status;
}

static bool app_modify_entry(struct Modify* modify, struct ModifyRsp* modify_rsp)
{
    bool status = true;
    status &= user_store_modify_password(modify);
    CHECK_STATUS(status, modify_rsp->ack = true);
    return status;
}

static bool app_read_entry(struct ReadEntry* read_entry, struct ReadEntryRsp* read_entry_rsp)
{
    bool status = true;
    status &= user_store_read_entry(read_entry, read_entry_rsp);
    CHECK_STATUS(status, cryptoctx_generate_iv());
    uint8_t* iv = cryptoctx_get_iv();
    gcm_encrypt(iv, NULL, 0, read_entry_rsp->wrapped_password, read_entry_rsp->wrapped_password, sizeof(read_entry_rsp->wrapped_password), read_entry_rsp->tag, GCM_TAG_LEN);

    memcpy(read_entry_rsp->initialization_vector, iv, GCM_IV_LEN);
    return status;
}