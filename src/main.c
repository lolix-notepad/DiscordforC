#include "discord-for-c.h"
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[])
{
    int res;
    char msg[20];

    sprintf(msg, "Pong: %d", rand());
    long long int channelID = 898466977645994004;
    res = sendSimpleMsg(channelID, msg);
    return 0;
}
