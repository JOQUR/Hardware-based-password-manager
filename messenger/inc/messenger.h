/**
 * @file messenger.h
 * @brief Header file for the messenger module.
 *
 * This file contains the declarations and macros for the messenger module
 * used in the Hardware-based Password Manager project.
 */

#ifndef MESSENGER_H_ 
#define MESSENGER_H_

#include "standard_def.h"
#include "messaging_bp.h"

typedef enum
{
    TERMINATED,
    ESTABLISHING,
    ESTABLISHED,
    ERROR
} ChannelStatus_t;

/**
 * @brief Structure representing the context of a communication channel.
 */
typedef struct ChannelContext
{
    ChannelStatus_t status;
    uint8_t client_public_key[32];
    uint8_t server_private_key[32];
} ChannelContext_t;


bool messenger_process_message(array_t* message, array_t* response, bool* send_reponse);

#endif