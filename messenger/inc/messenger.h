#ifndef MESSENGER_H_ 
#define MESSENGER_H_

#include <stdint.h>
#include "circular_buffer.h"

bool messanger_process_message(circular_buffer_t* buffer, circular_buffer_t buffer_len);

#endif