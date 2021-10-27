#ifndef SSL_TSL_CONNECTION
#define SSL_TSL_CONNECTION

#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

int sendSimpleMessage(long long int channelID, char* msg);
int create_socket(char[], char p[], BIO *);
void DisplayPublicKeyInfo(X509* cert, BIO* outbio);
void GetCertSignature(X509* cert, BIO* outbio);
int create_socket(char h[], char p[], BIO *out);
void ShowCerts(SSL* ssl, BIO* outbio);
char* buildRequest(long long int channelID, char* msg);

#endif
