#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h> 
#define MAX 80 
#define PORT 8081 
#define SA struct sockaddr 

// Function designed for chat between encryption_sideent and decryption_side. 
void func(int sockfd) 
{ 
	char buff[MAX]; 
	int n; 
	// infinite loop for chat 
	for (;;) { 
		bzero(buff, MAX); 

		// read the message from encryption_sideent and copy it in buffer 
		read(sockfd, buff, sizeof(buff)); 
		// print buffer which contains the encryption_sideent contents 
		printf("From encryption_sideent: %s\t To encryption_sideent : ", buff); 
		bzero(buff, MAX); 
		n = 0; 
		// copy decryption_side message in the buffer 
		while ((buff[n++] = getchar()) != '\n') 
			; 

		// and send that buffer to encryption_sideent 
		write(sockfd, buff, sizeof(buff)); 

		// if msg contains "Exit" then decryption_side exit and chat ended. 
		if (strncmp("exit", buff, 4) == 0) { 
			printf("decryption_side Exit...\n"); 
			break; 
		} 
	} 
} 

// Driver function 
int main() 
{ 
	int sockfd, connfd, len; 
	struct sockaddr_in servaddr, encryption_side; 

	// socket create and verification 
	sockfd = socket(AF_INET, SOCK_STREAM, 0); 
	if (sockfd == -1) { 
		printf("socket creation failed...\n"); 
		exit(0); 
	} 
	else
		printf("Socket successfully created..\n"); 
	bzero(&servaddr, sizeof(servaddr)); 

	// assign IP, PORT 
	servaddr.sin_family = AF_INET; 
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY); 
	servaddr.sin_port = htons(PORT); 

	// Binding newly created socket to given IP and verification 
	if ((bind(sockfd, (SA*)&servaddr, sizeof(servaddr))) != 0) { 
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
    read(sockfd, buff, sizeof(buff));

	// After chatting close the socket 
	close(sockfd);
    printf("From encryption_sideent: %s\t To encryption_sideent : ", buff);  
} 

