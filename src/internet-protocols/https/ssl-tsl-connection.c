#include "../../extras/colors-terminal.h"
#include "ssl-tsl-connection.h"

#define ENDPOINT "https://discord.com/api"
#define TOKEN_BOT getenv("TOKEN_BOT")
#define PORT "443"
#define HOST "discord.com"
#define REQUEST_FILE "/"

int lengthInt(long long int i) {
    return snprintf(NULL, 0, "%lld", i);
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

   printf("----\n"RESET);
}

/*Display  Public key Info */
void DisplayPublicKeyInfo(X509* cert  ,BIO* outbio) {
    printf(CYN"----Public-Key----\n");
    EVP_PKEY *pkey = NULL; 

    if ((pkey = X509_get_pubkey(cert)) == NULL)
        BIO_printf(outbio, RED"Error getting public key from certificate"RESET);

    if(!PEM_write_bio_PUBKEY(outbio, pkey))
        BIO_printf(outbio,RED "Error writing public key data in PEM format"RESET);

    printf("----\n"RESET);
}
