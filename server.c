#include <stdio.h> 
#include <netdb.h> 
#include <netinet/in.h> 
#include <stdlib.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <sys/types.h>

int main()
{
    int sockfd;
	int new_sock;

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == 0)
	{
		perror("socket failed");
		exit(EXIT_FAILURE);
	}
	// fprintf(stderr, "fd %d\n", sockfd);

	struct sockaddr_in encryption_side;
	struct sockaddr_in decryption_side;

	socklen_t enc_len = sizeof(encryption_side);
	socklen_t dec_len = sizeof(decryption_side);

	memset(&encryption_side, 0, sizeof(encryption_side));
	memset(&decryption_side, 0, sizeof(decryption_side));

	//populate address
	decryption_side.sin_family = AF_INET;
	decryption_side.sin_addr.s_addr = htonl(INADDR_ANY);
	decryption_side.sin_port = htons(8081);

	//bind
	if (bind(sockfd, (struct sockaddr *)&decryption_side, sizeof(decryption_side)) < 0)
	{
		perror("bind error\n");
		exit(0);
	}


	//listen
	if (listen(sockfd, 3) < 0)
	{
		perror("listen error");
		exit(0);
	}

	printf("waiting for connnection\n");

	if (new_sock = accept(sockfd, (struct sockaddr *)&encryption_side, (socklen_t *)&enc_len) < 0)
	{
		perror("accept error");
		exit(0);
	}
	fprintf(stderr, "new sock %d", new_sock);


	printf("connection from %s : %d\n", inet_ntoa(encryption_side.sin_addr), ntohs(encryption_side.sin_port));

	char buffer[1040];
	memset(buffer, 0, sizeof(buffer));
	int readret = read(new_sock, buffer, 1040);
    fprintf(stderr,"buffer %s\n", buffer);
    fprintf(stderr, "readret %d", readret);
}