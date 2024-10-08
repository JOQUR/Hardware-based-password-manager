
#include "stdint.h"
#include "stdio.h"
#ifndef NDEBUG
    #define PRINT(X)    printf("%s = %02hhX\r\n", __func__, X)
    #define PRINTS(X)    printf("%s: %s\n", __func__, X)
    #define PRINT_BUFFER(__BUFFER__, __SIZE__, __DESC__)    print_array(__BUFFER__, __SIZE__, __DESC__)
#else
    #define PRINT(X)    (X = X)
    #define PRINTS(X)
    #define PRINT_BUFFER(__BUFFER__, __SIZE__, __DESC__)
#endif


void print_array(uint8_t* buffer, uint16_t size, uint8_t* desc);