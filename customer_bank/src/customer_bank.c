#include "customer_bank.h" 
#include "string.h"

#define MAX_USERS   256

#ifdef __MINGW32__
    #pragma pack(1)
#endif
typedef struct data
{
    uint8_t description[64];
    uint8_t password[40];
} data_t;


#ifdef __MINGW32__
    #pragma pack(1)
#endif
typedef struct userstruct
{
    uint8_t id;
    uint8_t kek_len;
    uint8_t login[32];
    uint8_t kek[32];
    data_t data[5];
} userstruct_t;

static userstruct_t user_data[MAX_USERS];
static uint8_t counter;


static inline customer_bank_status_t checkAvailableSpace(void)
{
    return (counter < MAX_USERS) ? ST_OK : ST_END_OF_SPACE;
}


customer_bank_status_t customer_bank_init(void)
{
    memset(user_data, 0xff, sizeof(user_data));
}