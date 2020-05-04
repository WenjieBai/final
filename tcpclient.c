#include <netdb.h> 
#include <stdio.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#define MAX 80 
#define PORT 8081 
#define SA struct sockaddr 
void func(int sockfd) 
{ 
	char buff[MAX]; 
	int n; 
	for (;;) { 
		bzero(buff, sizeof(buff)); 
		printf("Enter the string : "); 
		n = 0; 
		while ((buff[n++] = getchar()) != '\n') 
			; 
		write(sockfd, buff, sizeof(buff)); 
		bzero(buff, sizeof(buff)); 
		read(sockfd, buff, sizeof(buff)); 
		printf("From Server : %s", buff); 
		if ((strncmp(buff, "exit", 4)) == 0) { 
			printf("encryption_sideent Exit...\n"); 
			break; 
		} 
	} 
} 

int main() 
{ 
	int sockfd, connfd; 
	struct sockaddr_in decryption_side, encryption_side; 

	// socket create and varification 
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
	decryption_side.sin_addr.s_addr = inet_addr("192.168.15.5"); 
	decryption_side.sin_port = htons(PORT); 

	// connect the encryption_sideent socket to server socket 
	if (connect(sockfd, (SA*)&decryption_side, sizeof(decryption_side)) != 0) { 
		printf("connection with the server failed...\n"); 
		exit(0); 
	} 
	else
		printf("connected to the server..\n"); 

	// function for chat 
	// func(sockfd);

    buff = "w cao l ";
    int ret = write(sockfd, buff, sizeof(buff));  
    fprintf("%s", buff);
	// close the socket 
	close(sockfd); 
} 
