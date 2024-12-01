#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> // read(), write(), close()
#include <assert.h>
#include "messenger.h"
#include "crypto_ctx.h"
#include "gcm.h"
#include "kwp.h"

#define PORT 8070
#define SA struct sockaddr 

void message_echange(int connfd);
static void prepare_and_read(int connfd, array_t* message, array_t* response);
static void test_gcm_encryption(void);
static void test_gcm_decryption(void);
static void test_kwp_wrapping(void);
static void test_kwp_unwrapping(void);

message_processor processor_cbk = messenger_process_message;

static void generate_random_arr(uint8_t* buff, uint16_t size)
{
    for(uint16_t i = 0; i < size; i++)
    {
        buff[i] = rand() % UINT8_MAX;
    }
}


int main(void)
{
    int sockfd, connfd, len;
    struct sockaddr_in servaddr = {0};
    struct sockaddr_in cli = {0};

#ifndef NDEBUG
    test_gcm_encryption();
    test_gcm_decryption();
    test_kwp_wrapping();
    test_kwp_unwrapping();
#endif
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd != -1);


    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 

    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    } 

    int listen_status = listen(sockfd, 1);
    assert(listen_status == 0);

    len = sizeof(cli);
    connfd = accept(sockfd, (SA*)&cli, &len); 
    if (connfd < 0) { 
        printf("server accept failed...\n"); 
        exit(0); 
    } 

    message_echange(connfd);

    close(sockfd);


    return 1;
}


void message_echange(int connfd)
{
    uint8_t rcv_buffer[256] = {0};
    uint8_t send_buffer[256] = {0};
    array_t message = {0};
    array_t response = {0};
    bool result = true;
    bool send_response = false;
    message.buffer = rcv_buffer;
    response.buffer = send_buffer;
    response.size = sizeof(send_buffer);

    result = cryptoctx_init();

    while(true)
    {
        if(result == false)
        {
            break;
        }
        prepare_and_read(connfd, &message, &response);
        CHECK_STATUS(result, processor_cbk(&message, &response, &send_response));
        if (result == true && (send_response == true))
        {
            send(connfd, response.buffer, response.size, 0);
        }
    }
    cryptoctx_deinit();
}


static void prepare_and_read(int connfd, array_t* message, array_t* response)
{
    memset(message->buffer, 0x00, 256);
    memset(response->buffer, 0x00, 256);
    size_t valread = read(connfd, message->buffer, 256);
    message->size = valread;
    response->size = 256;
}

static void test_gcm_encryption(void)
{
    uint8_t key[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    uint8_t iv[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    uint8_t add[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    uint8_t plain[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };
    uint8_t cipher[] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91
    };
    uint8_t exp_tag[] = {
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
        0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
    };

    gcm_context ctx;
    int ret = 0;
    uint8_t tag[16] = {0};
    uint8_t output[64] = {0};
    gcm_initialize();
    gcm_setkey(&ctx, key, sizeof(key));
    ret = gcm_crypt_and_tag(&ctx, ENCRYPT, iv, sizeof(iv), add, sizeof(add), plain, output, sizeof(plain), tag, sizeof(tag));
    gcm_zero_ctx(&ctx);

    ret |= memcmp(output, cipher, sizeof(cipher));
    ret |= memcmp(tag, exp_tag, sizeof(exp_tag));
    if(ret != 0)
    {
        printf("GCM encryption test failed\n");
    }
    else
    {
        printf("GCM encryption test passed\n");
    }
}

static void test_gcm_decryption(void)
{
    uint8_t key[] = {
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
    };
    uint8_t iv[] = {
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
    };
    uint8_t add[] = {
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2
    };
    uint8_t plain[] = {
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39
    };
    uint8_t cipher[] = {
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97, 0x3d, 0x58, 0xe0, 0x91
    };
    uint8_t exp_tag[] = {
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
        0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47
    };

    gcm_context ctx;
    int ret = 0;
    uint8_t tag[16] = {0};
    uint8_t output[64] = {0};
    gcm_initialize();
    gcm_setkey(&ctx, key, sizeof(key));
    ret = gcm_auth_decrypt(&ctx, iv, sizeof(iv), add, sizeof(add), cipher, output, sizeof(cipher), exp_tag, sizeof(exp_tag));
    gcm_zero_ctx(&ctx);
    ret |= memcmp(output, plain, sizeof(cipher));
    if(ret != 0)
    {
        printf("GCM decryption test failed\n");
    }
    else
    {
        printf("GCM decryption test passed\n");
    }
}


static void test_kwp_wrapping(void)
{
    uint8_t kek[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    uint8_t unwrapped_key[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    uint8_t wrapped_key[] = {
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
        0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
        0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
    };
    array_t kek_arr = {0};
    array_t unwrapped_key_arr = {0};
    array_t wrapped_key_arr = {0};
    array_t out = {0};

    uint8_t out_buff[sizeof(wrapped_key)] = {0};
    out.buffer = out_buff;
    out.size = sizeof(out_buff);
    kek_arr.buffer = kek;
    kek_arr.size = sizeof(kek);
    unwrapped_key_arr.buffer = unwrapped_key;
    unwrapped_key_arr.size = sizeof(unwrapped_key);
    wrapped_key_arr.buffer = wrapped_key;
    wrapped_key_arr.size = sizeof(wrapped_key);

    KW_Status_t status = kw_wrap_key(&kek_arr, &unwrapped_key_arr, &out);
    if (status == OK)
    {
        if(0 ==memcmp(out.buffer, wrapped_key, sizeof(wrapped_key)))
        {
            printf("Key wrapping test passed\n");
        }
        else
        {
            printf("Key wrapping test failed\n");
        }
    }
    else
    {
        printf("Key wrapping test failed\n");
    }
    
}

static void test_kwp_unwrapping(void)
{
    uint8_t kek[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    uint8_t wrapped_key[] = {
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47,
        0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B, 0x82,
        0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5
    };
    uint8_t expected_unwrapped_key[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
    };
    array_t kek_arr = {0};
    array_t wrapped_key_arr = {0};
    array_t unwrapped_key_arr = {0};
    array_t out = {0};

    uint8_t out_buff[sizeof(expected_unwrapped_key)] = {0};
    out.buffer = out_buff;
    out.size = sizeof(out_buff);
    kek_arr.buffer = kek;
    kek_arr.size = sizeof(kek);
    wrapped_key_arr.buffer = wrapped_key;
    wrapped_key_arr.size = sizeof(wrapped_key);
    unwrapped_key_arr.buffer = expected_unwrapped_key;
    unwrapped_key_arr.size = sizeof(expected_unwrapped_key);

    KW_Status_t status = kw_unwrap_key(&kek_arr, &wrapped_key_arr, &out);
    if (status == OK)
    {
        if(0 == memcmp(out.buffer, expected_unwrapped_key, sizeof(expected_unwrapped_key)))
        {
            printf("Key unwrapping test passed\n");
        }
        else
        {
            printf("Key unwrapping test failed\n");
        }
    }
    else
    {
        printf("Key unwrapping test failed\n");
    }
}
