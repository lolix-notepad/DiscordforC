#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

int socket_connect(char *host, in_port_t port){
	struct hostent *hp;
	struct sockaddr_in addr;
	int on = 1, sock;     

	if((hp = gethostbyname(host)) == NULL){
		herror("gethostbyname");
		exit(1);
	}

	bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;
	sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));

	if(sock == -1){
		perror("setsockopt");
		exit(1);
	}
	
	if(connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1){
		perror("connect");
		exit(1);

	}
	return sock;
}
 
#define BUFFER_SIZE 1024

int main(int argc, char *argv[]){
	int fd;
	char buffer[BUFFER_SIZE];

	if(argc < 3){
		fprintf(stderr, "Usage: %s <hostname> <port>\n", argv[0]);
		exit(1); 
	}

    char *API_ENDPOINT = "https://discord.com/api";
    char REQUEST[400];

    char  *start_line             = "POST /api/channels/<HERE_CHANNEL_ID>/messages HTTP/1.1\n";
    char  *header_host            = "Host: discord.com\n";
    char  *header_accept          = "Accept: application/json\n";
    char  *header_content_type    = "Content-Type: application/json\n";
    char  *header_authorization   = "Authorization: Bot <HERE_TOKEN_BOT>";
    char  *header_content_length  = "Content-Length: 15\n";
    char  *json                   = "{\"content\":\"a\"}\n";
    char  *end_line               = "\r\n";

    strcat(REQUEST, start_line);
    strcat(REQUEST, header_host);
    strcat(REQUEST, header_accept);
    strcat(REQUEST, header_content_type);
    strcat(REQUEST, header_authorization);
    strcat(REQUEST, header_content_length);
    strcat(REQUEST, json);
    strcat(REQUEST, end_line);
       
    printf("%s", REQUEST);
	fd = socket_connect(argv[1], atoi(argv[2])); 
    write(fd, REQUEST, strlen(REQUEST));
	bzero(buffer, BUFFER_SIZE);
	
	while(read(fd, buffer, BUFFER_SIZE - 1) != 0){
		fprintf(stderr, "%s", buffer);
		bzero(buffer, BUFFER_SIZE);
	}

	shutdown(fd, SHUT_RDWR); 
	close(fd); 

	return 0;
}
