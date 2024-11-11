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

#define PORT 8070
#define SA struct sockaddr 

void message_echange(int connfd);
static void prepare_and_read(int connfd, array_t* message, array_t* response);

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
    memset(message->buffer, 0xff, 256);
    memset(response->buffer, 0xff, 256);
    size_t valread = read(connfd, message->buffer, 256);
    message->size = valread;
    response->size = 256;
}