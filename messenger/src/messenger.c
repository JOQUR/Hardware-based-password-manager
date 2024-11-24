#include "messenger.h"
#include "string.h"
#include "debug.h"
#include "assert.h"
#include "crypto_ctx.h"
#include "user_context.h"
#include "app.h"
#include "gcm_api.h"

/**
 * @brief Initializes a ChannelContext_t structure with zero values.
 */
ChannelContext_t channel_ctx = {0};


/**
 * @brief External declaration of a message processor callback.
 *
 * This extern variable is used to reference a message processor callback function
 * that is defined elsewhere. The callback is intended to process messages in the
 * messenger module.
 */
extern message_processor processor_cbk;

static bool messenger_process_initialize_comm(struct InitializeComm* init_comm, struct InitializeCommRsp* init_comm_rsp);
static bool messenger_process_challenge(struct Challange* challange, struct ChallangeRsp* challange_rsp);
static bool messenger_process_finished_handshake(struct HandshakeFinished* handshake_finished, struct HandshakeFinishedRsp* handshake_finished_rsp);

static bool messanger_prepare_challange(uint8_t* buffer);

/**
 * @brief Processes an incoming message and generates an appropriate response.
 *
 * This function takes an incoming message, processes it, and generates a response
 * based on the content of the message. It also determines whether a response should
 * be sent back.
 *
 * @param message A pointer to the array_t structure containing the incoming message.
 * @param response A pointer to the array_t structure where the response will be stored.
 * @param send_response A pointer to a boolean that will be set to true if a response
 *                      should be sent, or false otherwise.
 * @return true if the message was processed successfully, false otherwise.
 */
bool messenger_process_message(array_t* message, array_t* response, bool* send_reponse)
{
    bool status = true;

    if (message == NULL || response == NULL) {
        status &= (message->size > 0);
    }
    status &= (0 != message->size);

    if (true == status)
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
                assert(channel_ctx.status == ESTABLISHING);
                *send_reponse = true;
            }
            break;

            // TODO: More sense would it have if client send buffer to challange
            case CHALLANGE:
            {
                CHECK_STATUS(status, messenger_process_challenge(&(messages.challange), &(responses.challange)));
                responses.id = CHALLANGE;
                assert(channel_ctx.status == ESTABLISHED);
                *send_reponse = true;
            }
            break;

            case HANDSHAKE_FINISHED:
            {
                CHECK_STATUS(status, messenger_process_finished_handshake(&(messages.handshake_finished), &(responses.handshake_finished)));
                responses.id = HANDSHAKE_FINISHED;
                assert(channel_ctx.status == ESTABLISHED);
                *send_reponse = true;
            }
            break;

            case START_APP:
            {
                if(messages.start_app && (channel_ctx.status == ESTABLISHED))
                {
                    processor_cbk = app_process_message;
                    PRINTS("APP STARTED");
                    *send_reponse = false;
                }
                else
                {
                    status &= false;
                    *send_reponse = false;
                }
            }
            break;
        
            default:
            {
                status &= false;
                *send_reponse = false;
            }
            break;
        }
        
        if(status)
        {
            response->size = sizeof(struct Responses);
            EncodeResponses(&responses, response->buffer);
        }
    }
    return status;
}


/**
 * @brief Processes the finished handshake message and generates a response.
 *
 * This function handles the final stage of the handshake process. It takes the
 * finished handshake message and produces a corresponding response.
 *
 * @param handshake_finished Pointer to the structure containing the finished handshake message.
 * @param handshake_finished_rsp Pointer to the structure where the response to the finished handshake will be stored.
 * @return true if the handshake was successfully processed and the response was generated, false otherwise.
 */
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

/**
 * @brief Prepares a challenge message.
 *
 * This function prepares a challenge message and stores it in the provided buffer.
 *
 * @param buffer Pointer to the buffer where the challenge message will be stored.
 * @return true if the challenge message was successfully prepared, false otherwise.
 */
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

/**
 * @brief Initializes the communication process.
 *
 * This function sets up the necessary parameters and structures to initialize
 * the communication process between the hardware-based password manager and
 * the corresponding communication interface.
 *
 * @param init_comm Pointer to the InitializeComm structure containing the
 *                  initialization parameters.
 * @param init_comm_rsp Pointer to the InitializeCommRsp structure where the
 *                      response of the initialization process will be stored.
 * @return true if the initialization is successful, false otherwise.
 */
static bool messenger_process_initialize_comm(struct InitializeComm* init_comm, struct InitializeCommRsp* init_comm_rsp)
{
    bool status = true;

    CHECK_STATUS(status, cryptoctx_set_client_public_key(init_comm->public_key));
    CHECK_STATUS(status, cryptoctx_generate_key_pair());
    CHECK_STATUS(status, cryptoctx_get_server_public_key(init_comm_rsp->public_key));
    CHECK_STATUS(status, cryptoctx_generate_shared_secret());
    if(true == status)
    {
        // cryptoctx_prepare_aes();
        gcm_init(cryptoctx_get_shared_secret(), 32);
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


/**
 * @brief Processes a challenge and generates a response.
 *
 * This function takes a challenge and processes it to generate a corresponding
 * challenge response.
 *
 * @param challange Pointer to the challenge structure to be processed.
 * @param challange_rsp Pointer to the challenge response structure to be filled.
 * @return true if the challenge was processed successfully, false otherwise.
 */
static bool messenger_process_challenge(struct Challange* challange, struct ChallangeRsp* challange_rsp)
{
    bool status = true; 
    cryptoctx_generate_iv();
    memcpy(challange_rsp->initialization_vector, cryptoctx_get_iv(), 12);
    CHECK_STATUS(status, gcm_encrypt(challange_rsp->initialization_vector, NULL, 0, challange->challange_buffer, challange_rsp->challange_buffer, 32, challange_rsp->tag, 16));
    channel_ctx.status = ESTABLISHED;
    return status;
}