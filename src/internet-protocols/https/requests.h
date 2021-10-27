#ifndef REQUESTS
#define REQUESTS

#include <openssl/err.h>

int create_socket(char h[], char p[], BIO *out);
SSL *createSSLConnection(char* HOST, char* PORT);
int sendRequest(char* HOST, char* PORT, char* request);

#endif
