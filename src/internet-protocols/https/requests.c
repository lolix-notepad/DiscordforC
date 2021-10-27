#include "../../extras/colors-terminal.h"

#include <stdio.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdlib.h>

#define BUFFER_SIZE 1024

struct sslConnectionStruct {
    SSL *ssl;
    X509 *cert;
    SSL_CTX *ctx;
    int server;
};

/* create_socket() : the socket & TCP-connect to server */
int create_socket(char h[], char p[], BIO *out) {
    int sockfd;
    char hostname[256] = "";
    char    portnum[6];
    char      proto[6] = "";
    char      *tmp_ptr = NULL;
    int           port;
    struct hostent *host;
    struct sockaddr_in dest_addr;
 
    strcpy(portnum,p);
    strcpy(hostname,h);
    port = atoi(portnum);

    if ((host = gethostbyname(hostname)) == NULL) {
        BIO_printf(out, "Error: Cannot resolve hostname %s.\n",  hostname);
        abort();
    }
 
    /* create the basic TCP socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    dest_addr.sin_family=AF_INET;
    dest_addr.sin_port=htons(port);
    dest_addr.sin_addr.s_addr = *(long*)(host->h_addr);

    /*reset the  struct*/
    memset(&(dest_addr.sin_zero), '\0', 8);
    tmp_ptr = inet_ntoa(dest_addr.sin_addr);

    /* Try to make the host connection */
    if ( connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) == -1 ) {
        BIO_printf(out, "Error: Cannot connect to host %s [%s] on port %d.\n",
        hostname, tmp_ptr, port);
    }

    return sockfd;
}

// SSL *createSSLConnection(char* HOST, char* PORT) {
struct sslConnectionStruct *createSSLConnection(char* HOST, char* PORT) {
    BIO *certbio         =  NULL;
    BIO *outbio          =  NULL;
    X509 *cert           =  NULL;
    X509_NAME *certname  =  NULL;
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    int server = 0;
    int ret, i;

    /** Debugging **/
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

    /** SSL PROCESSING **/

    /* Create the I/O BIO's */
    certbio = BIO_new(BIO_s_file());
    outbio  = BIO_new_fp(stdout, BIO_NOCLOSE);

    /* init SSL library */
    if(SSL_library_init() < 0)
        BIO_printf(outbio, "Could not initialize SSL_library_init !\n");

    /* Set SSLv2 client hello */
    method = SSLv23_client_method();

    /* new SSL context */
    if ((ctx = SSL_CTX_new(method)) == NULL)
        BIO_printf(outbio, "Unable to create a new SSL context SSL_CTX_new.\n");

    SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);

    /* Create new SSL connection state */
    ssl = SSL_new(ctx);

    /*  Make  TCP  connection */
    server = create_socket(HOST, PORT, outbio);
    if(server != 0)
        BIO_printf(outbio, "--Successfully made the TCP connection to: %s.\n", HOST);

    /* Attach the SSL session */
    SSL_set_fd(ssl, server);

    /* Try to SSL-connect here, returns 1 for success             */
    if (SSL_connect(ssl) != 1)
        BIO_printf(outbio, RED"!!!Error: Could not build a SSL session to: %s.\n"RESET, HOST);
    else
        BIO_printf(outbio, "--Successfully enabled SSL/TLS session to: %s.\n", HOST);

    /** END SSL PROCESSING **/

    struct sslConnectionStruct *sslStruct = malloc(sizeof(struct sslConnectionStruct));
    sslStruct->ssl = ssl;
    sslStruct->cert = cert;
    sslStruct->ctx = ctx;
    sslStruct->server = server;
    return sslStruct;
}

void cleanupSSLConnection(struct sslConnectionStruct *sslStruct) {
    /* Free the structures */
    SSL_free(sslStruct->ssl);
    close(sslStruct->server);
    X509_free(sslStruct->cert);
    SSL_CTX_free(sslStruct->ctx);
}

int sendRequest(char* HOST, char* PORT, char* request) {
    char buf[BUFFER_SIZE];

    struct sslConnectionStruct *sslStruct = createSSLConnection(HOST, PORT);
    int result = SSL_write(sslStruct->ssl, request, strlen(request));

    printf(BLU"Request : %s\n"RESET, request);
    printf("--Connected ->Encryption:  %s \n", SSL_get_cipher(sslStruct->ssl));
    printf("Write-Result = %i\n", result);
    printf(BLU"----end Request----\n");

    /* get response & decrypt */
    int bytes;
    printf(BLU"----Response----\n");

    for (;;) {
        bytes = SSL_read(sslStruct->ssl, buf, sizeof(buf)); 
        if (bytes == 0)
            break;
        if (bytes < 0) {
            printf(RED"Read Failed!\n"RESET);
            break;
        }
        buf[bytes] = 0;
        printf("%s\n", buf);
    }

    printf("--------\n"RESET);
    buf[bytes] = 0;

    cleanupSSLConnection(sslStruct);
    return 0;
}
