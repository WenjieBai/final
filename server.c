#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h>
#define PORT 8081 
#define SA struct sockaddr 

int main() 
{ 
	int sockfd, connfd, len; 
	struct sockaddr_in decryption_side, encryption_side; 

	// socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully created..\n"); 
	bzero(&decryption_side, sizeof(decryption_side)); 

	// assign IP, PORT 
	decryption_side.sin_family = AF_INET; 
	decryption_side.sin_addr.s_addr = htonl(INADDR_ANY); 
	decryption_side.sin_port = htons(PORT); 

	// Binding newly created socket to given IP and verification 
	if ((bind(sockfd, (SA*)&decryption_side, sizeof(decryption_side))) != 0) { 
		printf("socket bind failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully binded..\n"); 

	// Now decryption_side is ready to listen and verification 
	if ((listen(sockfd, 5)) != 0) { 
		printf("Listen failed...\n"); 
		exit(0); 
	} 
	else
		printf("decryption_side listening..\n"); 
        
	len = sizeof(encryption_side); 

	// Accept the data packet from encryption_sideent and verification 
	connfd = accept(sockfd, (SA*)&encryption_side, &len); 
	if (connfd < 0) { 
		printf("decryption_side acccept failed...\n"); 
		exit(0); 
	} 
	else
		{
            printf("decryption_side acccept the encryption_sideent...\n"); 
            printf("new fd %d\n", connfd);
        }

	// Function for chatting between encryption_sideent and decryption_side 
    char buff[MAX]; 
    read(sockfd, buff, sizeof(buff));

	// After chatting close the socket 
	close(sockfd);
    printf("From encryption_sideent: %s\t To encryption_sideent : ", buff);  
} 