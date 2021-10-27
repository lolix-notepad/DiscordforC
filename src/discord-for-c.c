#include "internet-protocols/https/requests.h"
#include "internet-protocols/https/ssl-tsl-connection.h"

#define HOST "discord.com"
#define PORT "443"

int sendSimpleMsg(long long int channelID, char* msg) {
    char* request = buildRequest(channelID, msg);
    int res = sendRequest(HOST, PORT, request);
    return 0;
}
