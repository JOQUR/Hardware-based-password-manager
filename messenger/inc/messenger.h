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

typedef struct ChannelContext
{
    ChannelStatus_t status;
    uint8_t client_public_key[32];
    uint8_t server_private_key[32];
} ChannelContext_t;


bool messenger_process_message(array_t* buffer, array_t* response);

#endif