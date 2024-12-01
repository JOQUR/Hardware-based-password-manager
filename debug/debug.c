#include "debug.h"

#ifndef NDEBUG

void print_array(uint8_t* buffer, uint16_t size, uint8_t* desc)
{
    printf("%s: ", desc);
    for (size_t i = 0; i < size; i++)
    {
        printf("%02x ", buffer[i]);
    }
    printf("\r\n");
    
}

#endif