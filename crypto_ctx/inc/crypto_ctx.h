#include "standard_def.h"

bool cryptoctx_init(void);
void cryptoctx_deinit(void);
void cryptoctx_generate_rand_byte(uint8_t* byte);
bool cryptoctx_set_client_public_key(uint8_t* pub_key);
void cryptoctx_generate_rand_buffer(uint8_t* buffer, size_t buffer_size);
bool cryptoctx_get_server_public_key(uint8_t* buffer);
bool cryptoctx_generate_key_pair(void);
bool cryptoctx_generate_shared_secret(void);
bool cryptoctx_encrypt(uint8_t* data, uint16_t len);

void cryptoctx_prepare_aes(void);

uint8_t* cryptoctx_get_iv(void);
uint8_t* cryptoctx_get_shared_secret(void);
bool cryptoctx_generate_iv(void);