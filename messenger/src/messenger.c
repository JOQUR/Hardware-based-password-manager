#include "messenger.h"
#include "string.h"
#include "debug.h"
#include "assert.h"
#include "crypto_ctx.h"

ChannelContext_t channel_ctx = {0};

static bool messenger_process_initialize_comm(struct InitializeComm* init_comm, struct InitializeCommRsp* init_comm_rsp);
static bool messenger_process_challenge(struct Challange* challange, struct ChallangeRsp* challange_rsp);
static bool messenger_process_finished_handshake(struct HandshakeFinished* handshake_finished, struct HandshakeFinishedRsp* handshake_finished_rsp);


static bool messanger_prepare_challange(uint8_t* buffer);

bool messenger_process_message(array_t* message, array_t* response)
{
    bool status = true;
    if ((NULL == message) || (NULL == response))
    {
        status &= false;
    }
    else
    {
        struct Messages messages = {0};
        struct Responses responses = {0};
        DecodeMessages(&messages, message->buffer);
        switch (messages.id)
        {
            case INITIALIZE_COMM:
            {

                CHECK_STATUS(status, messenger_process_initialize_comm(&(messages.init_comm), &(responses.init_comm)));
                responses.id = INITIALIZE_COMM;
                response->size = sizeof(struct Responses);
                assert(channel_ctx.status == ESTABLISHING);
            }
            break;

            // TODO: More sense would it have if client send buffer to challange
            case CHALLANGE:
            {
                status &= messenger_process_challenge(&(messages.challange), &(responses.challange));
                responses.id = CHALLANGE;
                response->size = sizeof(struct Responses);
                assert(channel_ctx.status == ESTABLISHED);
            }
            break;

            case HANDSHAKE_FINISHED:
            {
                status &= messenger_process_finished_handshake(&(messages.handshake_finished), &(responses.handshake_finished));
                responses.id = HANDSHAKE_FINISHED;
                response->size = sizeof(struct Responses);
                assert(channel_ctx.status == ESTABLISHED);
            }
            break;
        
            default:
            {
                status &= false;
            }
            break;
        }
        EncodeResponses(&responses, response->buffer);
    }
    return status;
}


static bool messenger_process_finished_handshake(struct HandshakeFinished* handshake_finished, struct HandshakeFinishedRsp* handshake_finished_rsp)
{
    bool status = true;
    if (true == handshake_finished->ack)
    {
        handshake_finished_rsp->ack = true;
    }
    else
    {
        status &= false;
    }

    return status;
}

static bool messanger_prepare_challange(uint8_t* buffer)
{
    bool status = true;
    if (NULL == buffer)
    {
        status &= false;
    }
    else
    {        
        for (size_t i = 0; i < 16; i++)
        {
            buffer[i] = i;
        }
    }
    return status;
}

static bool messenger_process_initialize_comm(struct InitializeComm* init_comm, struct InitializeCommRsp* init_comm_rsp)
{
    bool status = true;

    CHECK_STATUS(status, cryptoctx_set_client_public_key(init_comm->public_key));
    CHECK_STATUS(status, cryptoctx_generate_key_pair());
    CHECK_STATUS(status, cryptoctx_get_server_public_key(init_comm_rsp->public_key));
    CHECK_STATUS(status, cryptoctx_generate_shared_secret());
    memcpy(init_comm_rsp->initialization_vector, cryptoctx_get_iv(), sizeof(init_comm_rsp->initialization_vector));
    if(true == status)
    {
        cryptoctx_prepare_aes();
    }

    if (status)
    {
        channel_ctx.status = ESTABLISHING;
    }
    else
    {
        channel_ctx.status = TERMINATED;
    }
    return status;
}


static bool messenger_process_challenge(struct Challange* challange, struct ChallangeRsp* challange_rsp)
{
    bool status = true;

    // TODO: Make proper implementation, now its just echo
    memcpy(challange_rsp->challange_buffer, challange->challange_buffer, ARRAY_SIZE(challange->challange_buffer));
    assert(ARRAY_CMP(challange->challange_buffer, challange_rsp->challange_buffer, ARRAY_SIZE(challange->challange_buffer)));
    channel_ctx.status = ESTABLISHED;
    cryptoctx_encrypt(challange_rsp->challange_buffer, ARRAY_SIZE(challange->challange_buffer));
    PRINT_BUFFER(challange_rsp->challange_buffer, 32, "CHALLANGE");
    PRINT(channel_ctx.status);
    return status;
}
