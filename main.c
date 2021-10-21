#include "ssl-tsl-connection.h"

int main (int argc, char *argv[])
{
    int res;
    long long int channelID = 898466977645994004;
    res = sendSimpleMessage(channelID, __DATE__);
    return 0;
}
