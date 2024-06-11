#ifndef CUSTOMER_BANK_H_ 
#define CUSTOMER_BANK_H_

#include <stdio.h>
#include <stdint.h>


typedef enum {
    ST_OK,
    ST_NOK,
    ST_END_OF_SPACE
} customer_bank_status_t;


customer_bank_status_t customer_bank_init(void);

#endif