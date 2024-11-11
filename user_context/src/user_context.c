#include "user_context.h"
#include "assert.h"
#include "debug.h"
#include "string.h"

#define SAME_BUFFER             0
#define DIFF_BUFFER             1
static user_ctx_t user_ctx;



bool user_ctx_init(uint8_t* login, uint8_t* pass_hash)
{
    bool status = true; 
    memcpy(user_ctx.login, login, ARRAY_SIZE(user_ctx.login));
    memcpy(user_ctx.pass_hash, pass_hash, ARRAY_SIZE(user_ctx.pass_hash));
    user_ctx.isLogged == false;
    return status;
}

bool user_ctx_verify_user(uint8_t* login, uint8_t* pass_hash)
{
    bool status = true; 
    
    if(ARRAY_CMP(login, user_ctx.login, ARRAY_SIZE(user_ctx.login)))
    {
        status &= true;
        PRINTS("YAY!!");
    }

    if(ARRAY_CMP(pass_hash, user_ctx.pass_hash, ARRAY_SIZE(user_ctx.pass_hash)))
    {
        status &= true;
        PRINTS("YAY!!");
    }

    return status;
}