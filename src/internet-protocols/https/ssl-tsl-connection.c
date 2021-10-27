#include "../../extras/colors-terminal.h"
#include "requests.h"
#include "ssl-tsl-connection.h"

#define ENDPOINT "https://discord.com/api"
#define TOKEN_BOT getenv("TOKEN_BOT")
#define PORT "443"
#define HOST "discord.com"
#define REQUEST_FILE "/"

int lengthInt(long long int i) {
    return snprintf(NULL, 0, "%lld", i);
}

int sendSimpleMessage(long long int channelID, char* msg) {
    BIO *certbio         =  NULL;
    BIO *outbio          =  NULL;
    X509 *cert           =  NULL;
    X509_NAME *certname  =  NULL;
    char *regparam = REQUEST_FILE;
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    int server = 0;
    int ret, i;

    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings();

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

    ShowCerts(ssl,outbio);

    /* --- Send --- */
    printf(BLU"----Request----\n");

    char buf[1024];

    char* request = buildRequest(channelID, msg);

    int result = SSL_write(ssl, request, strlen(request));

    printf(BLU"Request : %s\n"RESET, request);
    printf("--Connected ->Encryption:  %s \n", SSL_get_cipher(ssl));
    printf("Write-Result = %i\n", result);
    printf(BLU"----end Request----\n");

    /* encrypt & send message */
    int bytes;
    int s = 0; 

    printf(BLU"----Response----\n");

    for (;;) {
        /* get response & decrypt */
        bytes = SSL_read(ssl, buf, sizeof(buf)); 
        if (bytes == 0) {
            break;
        } else if (bytes < 0) {
            printf(RED"Read Failed!\n"RESET);
            break;
        } else {
            buf[bytes] = 0;
            printf("%s\n", buf);
        }
    }

    printf("--------\n"RESET);
    buf[bytes] = 0;
        
    /* Free the structures */
    SSL_free(ssl);
    close(server);
    X509_free(cert);
    SSL_CTX_free(ctx);
    BIO_printf(outbio, "Finished SSL/TLS connection with Host: %s.\n", HOST);
        
    return 0;
}


char* buildRequest(long long int channelID, char* msg) {
    char *start_line                  = "POST /api/channels/%lld/messages HTTP/1.1\r\n";
    char *header_host                 = "Host: discord.com\r\n";
    char *header_connection           = "Connection: close\r\n";
    char *header_content_type         = "Content-Type: application/json\r\n";
    char *header_authorization_base   = "Authorization: Bot %s\r\n";
    char *header_content_length_base  = "Content-Length: %d\r\n\r\n";
    char *json_base                   = "{\"content\":\"%s\"}\r\n";

    char json[strlen(json_base) + strlen(msg)];
    sprintf(json, json_base, msg);

    int len_request = strlen(start_line) + strlen(header_host) + 
            strlen(header_connection) + strlen(header_content_type) +
            strlen(header_authorization_base) + strlen(header_content_length_base) +
            strlen(json) + lengthInt(channelID) + strlen(TOKEN_BOT) + 
            lengthInt(strlen(json)) + strlen(msg);

    char *request_base = malloc(len_request);
    char *request = malloc(len_request);

    strcpy(request_base, start_line);
    strcat(request_base, header_host);
    strcat(request_base, header_connection);
    strcat(request_base, header_content_type);
    strcat(request_base, header_authorization_base);
    strcat(request_base, header_content_length_base);
    strcat(request_base, json_base);
    sprintf(request, request_base, channelID, TOKEN_BOT, strlen(json), msg);

    return request;
}

/* Show  Certificate Information */
void ShowCerts(SSL* ssl, BIO* outbio) {   
    X509 *cert;
    char *line;

    /* get the server's certificate */
    cert = SSL_get_peer_certificate(ssl); 
    if (cert != NULL) {
        printf(GRN"----Server certificate----\n"RESET);
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf(MAG"Subject: %s\n"RESET, line);
        free(line);      
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf(MAG"Issuer: %s\n"RESET, line);
        GetCertSignature(cert ,outbio);
        DisplayPublicKeyInfo(cert, outbio);
        free(line);       
        X509_free(cert);    
    } else
        printf(RED" No client certificates ...\n"RESET);
    printf(GRN"----End Certificate----\n"RESET);
}

/* Show Certificate Signature*/
void GetCertSignature(X509* cert, BIO* outbio) {
    printf(YEL "----Signature----\n");
    ASN1_STRING *asn1_sig = NULL;
    ASN1_BIT_STRING *asn1_sig_me = NULL;
    X509_ALGOR *sig_type = NULL;
    size_t sig_bytes = 0;

    /* const ASN1_BIT_STRING *signature_me;
    X509_get0_signature(&signature_me, NULL, cert);

    sig_type = signature_me->sig_alg;
    asn1_sig = cert->signature; */
    // sig_type = cert->sig_alg;
    // asn1_sig = cert->signature;
    /* sig_bytes = asn1_sig->length;

    BIO_printf(outbio, "Signature Algorithm:\n");
    if (i2a_ASN1_OBJECT(outbio, sig_type->algorithm) <= 0)
        BIO_printf(outbio, "Error getting the signature algorithm.\n");
    else BIO_puts(outbio, "\n\n");

    BIO_printf(outbio, "Signature Length:\n%d Bytes\n\n", sig_bytes);
    BIO_printf(outbio, "Signature Data:");
    if (X509_signature_dump(outbio, asn1_sig, 0) != 1)
        BIO_printf(outbio, "Error printing the signature \n"); */

   printf("----\n"RESET);
}

/*Display  Public key Info */
void DisplayPublicKeyInfo(X509* cert  ,BIO* outbio) {
    printf(CYN"----Public-Key----\n");
    EVP_PKEY *pkey = NULL; 

    if ((pkey = X509_get_pubkey(cert)) == NULL)
        BIO_printf(outbio, RED"Error getting public key from certificate"RESET);

    /* if (pkey) {
        switch (pkey->type) {
            case EVP_PKEY_RSA:
                BIO_printf(outbio, "%d bit RSA Key\n\n", EVP_PKEY_bits(pkey));
                break;
            case EVP_PKEY_DSA:
                BIO_printf(outbio, "%d bit DSA Key\n\n", EVP_PKEY_bits(pkey));
                break;
            default:
                BIO_printf(outbio, "%d bit non-RSA/DSA Key\n\n", EVP_PKEY_bits(pkey));
                break;
        }
    } */

    if(!PEM_write_bio_PUBKEY(outbio, pkey))
        BIO_printf(outbio,RED "Error writing public key data in PEM format"RESET);

    printf("----\n"RESET);
}


//348 lines
