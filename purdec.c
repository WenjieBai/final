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

#define DEBUG 0

//Create crypto handler at global scope
gcry_cipher_hd_t crypto;
char *filename;
char *filename_suffix;

int local_mode;
int distant_mode;

void localmode(char *password);
void distantmode(char *port, char *password);

void initialize_handler(char *password, char *vector)
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
			password,
			strlen(password),
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
			// distantmode(argv[2], password);
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
	char* vector= "InitializationVector";
  	initialize_handler(password, vector);

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
	char *in_buffer = malloc(2048);
	int freadret;

	while (freadret = fread(in_buffer, 1, 1040, in))
	{
		//Buffer for unencrypted data
		size_t out_size = 2048;
		char *out_buffer = malloc(2048);

		if (!decrypt(crypto, out_buffer, out_size, in_buffer, 2048))
		{
			printf("Read %d bytes of data. Writing %i bytes of Data.\n", freadret, freadret - 16);
			fwrite(out_buffer, freadret - 16, 1, out);
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


	struct sockaddr_in encryption_side;
	struct sockaddr_in decryption_side;
	socklen_t enc_len = sizeof(struct sockaddr_in);

	//create socket aand new_socketfd
	int sockfd;
	int new_socketfd;

	//setup
	decryption_side.sin_family = AF_INET;
	decryption_side.sin_addr.s_addr = INADDR_ANY;
	decryption_side.sin_port = htons(port);

	//bind
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (bind(sockfd, (struct sockaddr *)&decryption_side, sizeof(struct sockaddr)) < 0)
	{
		perror("bind error\n");
		exit(0);
	}

	//listen
	if (listen(sockfd, 1) < 0)
	{
		perror("listen error");
		exit(0);
	}

	printf("waiting for connnection\n");

	if (new_socketfd = accept(sockfd, (struct sockaddr *)&encryption_side, &enc_len) < 0)
	{
		perror("accept error");
		exit(0);
	}
	if (getsockname(new_socketfd, (struct sockaddr *)&encryption_side, &enc_len) == -1)
	{
		perror("getsockname error\n");
	}

	printf("connection from %s : %d", inet_ntoa(encryption_side.sin_addr), ntohs(encryption_side.sin_port));

	// phrase 1: receive filename and IV
	char *filename = malloc(20);;
	int recvret;
	if(recvret = recv(new_socketfd, filename, 20, 0) < 0)
	{
		perror("filename\n");
	}
	printf("file name %s\n",filename);


	char *IV = malloc(16);
	if((recvret = recv(new_socketfd, IV, 16, 0)) < 0)
	{
		perror("recv iv.\n");
	}
	IV[16] = '\0';

	//Configure glib and file handler
	crypt_init(password, IV);

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
	char * in_buffer = malloc(2048);
	int filesize = 0;
	int writesize = 0;
	while (1)
	{
		recvret = recv(new_socketfd, in_buffer, 1040, 0);
		in_buffer[recvret] = '\0';

		//dencrypt the data
		size_t out_size = 2048;
		unsigned char *out_buffer = malloc(2048);

		if (recvret > 0 && !decrypt(crypto, out_buffer, out_size, in_buffer, 2048))
		{

			if (recvret < 1024)
			{
				out_buffer[recvret - 19] = '\0';
				fwrite(out_buffer, recvret - 19, 1, out);
				writesize += recvret - 19;
			}
			else
			{
				out_buffer[recvret - 16] = '\0';
				fwrite(out_size, recvret - 16, 1, out);
				writesize += recvret - 16;
			}
			fflush(out);
			printf("Recieved %d bytes of data. Writing %i bytes of Data.\n", recvret, writesize);
			filesize += writesize;
		}

		free(out_buffer);

		char *trans_complete = "transmissioncompleted";
		if (strcmp(in_buffer,trans_complete) == 0)
		{
			printf("Transmission completed");
			break;
		}

		memset(in_buffer, 0, 1040);
	}

	fclose(out);
	free(in_buffer);
	gcry_cipher_close(crypto);
}



