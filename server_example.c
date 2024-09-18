#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#include <unistd.h> // read(), write(), close()
#include <assert.h>
#include "AES.h"
#include "compact25519.h"
#include "messaging_bp.h"
#include "messenger.h"

#define PORT 8070
#define SA struct sockaddr 

void message_echange(int connfd);

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

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd != -1);


    servaddr.sin_family = AF_INET; 
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
    servaddr.sin_port = htons(PORT); 

    if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
        printf("socket bind failed...\n"); 
        exit(0); 
    } 
    assert(listen(sockfd, 1) == 0);

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

    struct Msg message_construct = {.msg = PUBLIC_KEY_ECHANGE, .res = ACK};
    uint8_t* iv = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf";
    struct AES_ctx ctx, ctx2;
    struct PublicKeyExchange pkExchange = {0};
    char buff[sizeof(message_construct)] = {0};
    char pkBuff[sizeof(pkExchange)] = {0};
    uint8_t seed1[X25519_KEY_SIZE];
    uint8_t sec1[X25519_KEY_SIZE];
    uint8_t pub1[X25519_KEY_SIZE];
    uint8_t shared1[X25519_SHARED_SIZE];
    uint8_t* data = "\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf";
    uint8_t dataarr[16] = {0};
    memcpy(dataarr, data, 16);
    generate_random_arr(seed1, sizeof(seed1));
    compact_x25519_keygen(sec1, pub1, seed1);
    EncodeMsg(&message_construct, buff);

    // send ack
    send(connfd, buff, sizeof(buff), 0);

    // read pub key from client
    int valread = read(connfd, pkBuff, sizeof(pkBuff));
    if(valread != sizeof(pkBuff))
    {
        printf("FAILED\r\n");
    }

    DecodePublicKeyExchange(&pkExchange, pkBuff);
    
    // using external pubkey calculate shared key
    compact_x25519_shared(shared1, sec1, pkExchange.pub_key);
    AES_init_ctx_iv(&ctx, shared1, iv);
    AES_CBC_encrypt_buffer(&ctx, dataarr, 16);
    // for (int i = 0; i < sizeof(pkBuff); i++)
    // {
    //     printf("pkBuff[%d] = %x\r\n", i, pkExchange.pub_key[i]);
    // }

    // zero pub key struct
    memset(pkExchange.pub_key, 0x00, sizeof(pkExchange.pub_key));

    // send server public key
    memcpy(pkExchange.pub_key, pub1, sizeof(pub1));
    EncodePublicKeyExchange(&pkExchange, pkBuff);
    send(connfd, pkBuff, sizeof(pkBuff), 0);
    for (int i = 0; i < sizeof(sec1); i++)
    {
        printf("pubkey[%d] = %x\r\n", i, pub1[i]);
    }
    for (int i = 0; i < sizeof(shared1); i++)
    {
        printf("shared secret[%d] = %x\r\n", i, shared1[i]);
    }
    send(connfd, dataarr, 16, 0);
}