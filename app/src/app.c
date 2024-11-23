#include "app.h"
#include "debug.h"
#include "crypto_ctx.h"
#include "user_context.h"
#include "user_store.h"

static bool app_generate_password(bool generate, struct GenerateRsp* generate_rsp);
static bool app_process_login(struct Login* login, struct LoginRsp* login_rsp);
static bool app_process_new_entry(struct AddEntry* new_entry, struct AddEntryRsp* new_entry_rsp);

extern bool messenger_process_message(array_t* message, array_t* response, bool* send_reponse);
extern message_processor processor_cbk;

bool app_process_message(array_t* message, array_t* response, bool* send_reponse)
{
    bool status = true;
    status &= !((NULL == message) || (NULL == response));
    status &= (0 != message->size);
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
                *send_reponse = true;
            }
            break;

            case GENERATE:
            {
                status &= app_generate_password(&app_message.generate, &(app_reponse.generate));
                app_reponse.node_id = GENERATE;
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
    status &= user_store_add_new_entry(new_entry);

    new_entry_rsp->ack = status;

    return status;
} 

static bool app_generate_password(bool generate, struct GenerateRsp* generate_rsp)
{
    bool status = true;

    if (true == generate)
    {
        cryptoctx_generate_rand_buffer(generate_rsp->generated_password, sizeof(generate_rsp->generated_password));
    }
    else
    {
        status = false;
    }

    return status;
}
