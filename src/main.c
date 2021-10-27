#include "discord-for-c.h"
#include <stdio.h>
#include <stdlib.h>

int main (int argc, char *argv[])
{
    long long int channelID = 111111111111111111;
    char* msg = "example";
    int res = sendSimpleMsg(channelID, msg);
    return 0;
}
