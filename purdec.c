#include <stdio.h>
#include <errno.h>
#include <gcrypt.h>
#include <gcrypt-module.h>

#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "openssl/sha.h"

#define DEBUG 0

//Create crypto handler at global scope
gcry_cipher_hd_t crypto;
char *filename;
char *filename_suffix;

int local_mode;
int distant_mode;

void localmode(char *password);
void distantmode(char *port, char *password);

void initialize_handler(char *password, char *vector, char *salt)
{
	char *key[32];
	unsigned int key_len = 32;

	//Hash the Password
	gcry_error_t cryptoError =
		gcry_kdf_derive(
			password,
			strlen(password),
			GCRY_KDF_PBKDF2,
			GCRY_MD_SHA256,
			salt,
			strlen(salt),
			1024,
			key_len,
			key);

	if (cryptoError)
	{
		printf("Error.\n");
	}

	cryptoError =
		gcry_cipher_open(
			&crypto,
			GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_ECB,
			0);

	if (cryptoError)
	{
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		exit(0);
	}

	//set cipher key
	cryptoError = gcry_cipher_setkey(crypto, key, key_len);
	if (cryptoError)
	{
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		exit(0);
	}

	//set initialization vector
	size_t vector_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	cryptoError =
		gcry_cipher_setiv(crypto, vector, vector_len);

	if (cryptoError)
	{
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		exit(0);
	}
}


void hmac(
    const unsigned char *data, /* pointer to data stream        */
    int data_len,              /* length of data stream         */
    const unsigned char *key,  /* pointer to authentication key */
    int key_len,               /* length of authentication key  */
    char *output)
{
    unsigned char md_value[32]; //32 byte
    unsigned int md_len;

    HMAC(EVP_sha256(), key, key_len, data, data_len, md_value, &md_len);

    memcpy(output, md_value, md_len);

}


int decrypt(gcry_cipher_hd_t h, unsigned char *out, size_t outsize, unsigned char *in, size_t inlen)
{

	gcry_error_t cryptoError = gcry_cipher_decrypt(
		h,		 //gcry_cipher_hd_t h
		out,	 //unsigned char *out
		outsize, //size_t outsize
		in,		 //const unsigned char *in
		inlen);	 //size_t inlen

	if (cryptoError)
	{
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}
	else
	{
		return 0;
	}
}

int main(int argc, char *argv[])
{

	filename = malloc(20);
	filename_suffix = malloc(23);
	char password[16]; //Need in high scope

	printf("Password: ");
	fgets(password, sizeof password, stdin);

	if (argc > 3)
	{
		printf("\n\nUsage: purdec [-d] [-1 <input file>]\n");
		exit(0);
	}
	else
	{
		//Set proper mode
		if (!strcmp(argv[1], "-l"))
		{
			local_mode = 1;
			filename_suffix = argv[2];
			strcpy(filename, filename_suffix);
			filename[strlen(filename_suffix) - 1] = 0;
			filename[strlen(filename_suffix) - 2] = 0;
			filename[strlen(filename_suffix) - 3] = 0;
			filename[strlen(filename_suffix) - 4] = 0;

			localmode(password);
		}
		else if (!strcmp(argv[1], "-d"))
		{
			distant_mode = 1;
			distantmode(argv[2], password);
		}
		else
		{
			perror("argument can either be -l or -d\n");
			exit(0);
		}
	}
}

void localmode(char *password)
{
	printf("local mode\n");

	// initialize crypto handler
	char *vector = "InitializationVector";
	char *salt = "IamSaltValue";
	initialize_handler(password, vector, salt);

	//Create file handler and file buffer
	FILE *in;
	FILE *out;

	//Open the file
	in = fopen(filename_suffix, "r");
	out = fopen(filename, "w");

	//File opening error detection
	if (in == NULL || out == NULL)
	{
		printf("Error opening ");
		if (in == NULL)
		{
			printf("in");
		}
		if (out == NULL)
		{
			printf("out");
		}
		printf(" file.\n");
	}

	//decrypt the data from file
	char *in_buffer = malloc(1040);
	int freadret;

	while (freadret = fread(in_buffer, 1, 1040, in))
	{
		//Buffer for unencrypted data
		size_t out_size = 2048;
		char *out_buffer = malloc(out_size);

		if (!decrypt(crypto, out_buffer, out_size, in_buffer, 1040))
		{
			fwrite(out_buffer, freadret - 16, 1, out);
			printf("Read %d bytes of data. Writing %i bytes of Data.\n", freadret, freadret - 16);
		}

		free(out_buffer);
	}

	//Close the file
	fclose(in);
	fclose(out);

	//Free memory
	free(in_buffer);
}

void distantmode(char *port, char *password)
{
	printf("distant mode\n");

	int sockfd, connfd, len;
	struct sockaddr_in server, client;

	// socket create and verification
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		printf("socket creation failed...\n");
		exit(0);
	}
	else
	{
		printf("Socket successfully created..\n");
	}
	bzero(&server, sizeof(server));

	// assign IP, PORT
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(atoi(port));

	// Binding newly created socket to given IP and verification
	if ((bind(sockfd, (struct sockaddr *)&server, sizeof(server))) != 0)
	{
		printf("socket bind failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully binded..\n");

	// Now server is ready to listen and verification
	if ((listen(sockfd, 5)) != 0)
	{
		printf("Listen failed...\n");
		exit(0);
	}
	else
		printf("Server listening..\n");
	len = sizeof(client);

	// Accept the data packet from client and verification
	connfd = accept(sockfd, (struct sockaddr *)&client, &len);
	if (connfd < 0)
	{
		printf("server acccept failed...\n");
		exit(0);
	}
	else
	{
		printf("server acccept the client...\n");
		printf("connfd %d", connfd);
	}

	printf("connection from %s : %d\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port));

	// phrase 1: receive filename and IV salt mac key
	char *filename = malloc(20);
	int recvret;

	if (recvret = read(connfd, filename, 20) < 0)
	{
		perror("filename error\n");
	}
	else
	{
		printf("file name %s\n", filename);
	}

	char *IV = malloc(16);
	if ((recvret = recv(connfd, IV, 16, 0)) < 0)
	{
		perror("recv iv error.\n");
	}
	else
	{
		IV[16] = '\0';
		// printf("IV %s", IV);
	}

	// recv salt
	char *salt = malloc(16);
	if ((recvret = recv(connfd, salt, 16, 0)) < 0)
	{
		perror("recv salt error.\n");
	}

	// recv mac key
	char *mac_buffer = malloc(32);
	char *mac_key = malloc(32);
	if ((recvret = recv(connfd, mac_key, 32, 0)) < 0)
	{
		perror("recv salt error.\n");
	}
	printf("mac key %s", mac_key);

	//Configure glib and file handler
	initialize_handler(password, IV, salt);

	FILE *out;
	if (out = fopen(filename, "r"))
	{
		printf("File %s already exists. Exiting.\n", filename);
		exit(0);
	}
	else
	{
		out = fopen(filename, "w");
	}

	//phrase 2: receive encrypted data
	char *in_buffer = malloc(2048);
	int filesize = 0;
	int writesize = 0;
	while (1)
	{
		recvret = recv(connfd, in_buffer, 1040, 0);
		in_buffer[recvret] = '\0';

		//dencrypt the data
		size_t out_size = 2048;
		unsigned char *out_buffer = malloc(out_size);

		if (recvret > 0 && !decrypt(crypto, out_buffer, out_size, in_buffer, 1040))
		{

			out_buffer[recvret - 16] = '\0';
			fwrite(out_buffer, recvret - 16, 1, out);
			writesize = recvret - 16;

			fflush(out);
			filesize += recvret;
			printf("Recieved %d bytes of data. Writing %i bytes of Data.\n", recvret, writesize);

			hmac(in_buffer, 1040, mac_key, 32, mac_buffer);
			
		}	
	
		free(out_buffer);

		// char *trans_complete = "transmissioncompleted";
		// if (strcmp(in_buffer, trans_complete) == 0)
		// {
		// 	printf("Transmission completed");
		// 	break;
		// }
		if (recvret < 1040)
		{
			break;
		}

		memset(in_buffer, 0, 1040);
	}

	printf("mac buffer %s", mac_buffer);
	printf("file size %d\n", filesize);
	fclose(out);
	free(in_buffer);
	gcry_cipher_close(crypto);
}
