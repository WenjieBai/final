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
#include <time.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include "openssl/sha.h"

gcry_cipher_hd_t crypto;
gcry_error_t macErr;

char *filename;
char *filename_suffix;
int local_mode;
int distant_mode;
int total_size;

void localmode(char *password);
void distantmode(char *address, char *password);

void gen_random(char *s, const int len)
{
	static const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
	srand(time(0));

	int i;

	for (i = 0; i < len; ++i)
	{
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

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

int main(int argc, char *argv[])
{

	int local_mode;
	filename = malloc(20);
	filename_suffix = malloc(23);
	char *argument = malloc(4);

	if (argc <= 2)
	{
		printf("\n\nUsage: purenc <input file> [-d <output IP-addr:port>] [-l] (One argument required)\n");
		return 1;
	}
	else
	{
		//get filename
		filename = argv[1];
		strcpy(filename_suffix, filename);
		strcat(filename_suffix, ".pur");

		argument = argv[2];

		// set mode
		if (strcmp(argument, "-l") == 0)
		{
			local_mode = 1;
		}
		if (strcmp(argument, "-l") == 0)
		{
			distant_mode = 1;
		}
	}

	//enter password
	char password[16];
	printf("Password: ");
	fgets(password, sizeof password, stdin);

	if (local_mode == 1)
	{
		localmode(password);
	}
	if (distant_mode == 0)
	{
		distantmode(argv[3], password);
	}
}

void localmode(char *password)
{
	printf("local mode\n");
	char *vector = "InitializationVector";
	char *salt = "IamSaltValue";
	initialize_handler(password, vector, salt);
	//Create file handler and file buffer
	FILE *in;
	FILE *out;

	//Open the file
	in = fopen(filename, "r");

	if (out = fopen(filename_suffix, "r"))
	{
		printf("File %s already exists. Exiting.\n", filename_suffix);
		exit(0);
	}
	else
	{
		out = fopen(filename_suffix, "w");
	}

	//Error detection
	if (in == NULL || (out == NULL))
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
		perror(" file.\n");
		exit(0);
	}

	//Print file contents to another file
	int readret;
	int total = 0;
	char *in_buffer = malloc(1024);

	while (readret = fread(in_buffer, 1, 1024, in))
	{
		//Buffer for encrypted data
		size_t out_size = readret + 1024;
		char *out_buffer = malloc(readret + 1024);

		//encrypt data
		gcry_error_t gcryErr = gcry_cipher_encrypt(
			crypto,		//gcry_cipher_hd_t h
			out_buffer, //unsigned char *out
			out_size,	//size_t out_size
			in_buffer,	//const unsigned char *in
			1024);		//size_t inlen

		if (gcryErr)
		{
			printf("%s: %s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
			exit(0);
		}
		else
		{
			fwrite(out_buffer, readret + 16, 1, out);
			printf("Read %d bytes of data. Writing %i bytes of Data.\n", readret, readret + 16);
		}
		free(out_buffer);
	}
}

void distantmode(char *address, char *password)
{
	size_t vector_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	char *vector = malloc(vector_len);
	gen_random(vector, vector_len);
	// printf("iv %s", vector);
	char *salt = malloc(vector_len);
	gen_random(salt, vector_len);
	initialize_handler(password, vector, salt);

	char *ip = strtok(address, ":");
	char *port = strtok(NULL, ":");
	printf("ip: %s port: %d\n", ip, atoi(port));

	//create socket struct
	struct sockaddr_in server;
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		printf("socket creation failed...\n");
		exit(0);
	}
	else
		printf("Socket successfully created..\n");

	//setup
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(ip);
	server.sin_port = htons(atoi(port));

	//connect
	if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) == -1)
	{
		perror("connect error\n");
		exit(0);
	}

	//phrase 1: send filename and initlization vector
	int writeret;
	if (writeret = write(sockfd, filename, 20) <= 0)
	{
		perror("file name\n");
		error(0);
	}
	else
	{
		printf("file name %s, writeret %d\n", filename, writeret);
	}

	if (writeret = write(sockfd, vector, vector_len) < 0)
	{
		perror("IV error\n");
		exit(0);
	}

	//send salt
	if (writeret = write(sockfd, salt, vector_len) < 0)
	{
		perror("salt error\n");
		exit(0);
	}

	//send mac key
	char *mac_buffer = malloc(32);
	char *mac_key = malloc(32); 
	gen_random(mac_key, 32);
	if (writeret = write(sockfd, mac_key, 32) < 0)
	{
		perror("mac key\n");
		exit(0);
	}
	printf("mac key %s", mac_key);

	//phrase 2: send encrypted data
	FILE *in;
	in = fopen(filename, "r");
	char *in_buffer = malloc(1040);


	int readret;

	while ((readret = fread(in_buffer, 1, 1024, in)) > 0)
	{

		printf("read %d bytes, ", readret);

		//Buffer for encrypted data
		size_t out_size = readret + 1024;
		char *out_buffer = malloc(out_size);

		//encryption
		gcry_error_t gcryErr = gcry_cipher_encrypt(
			crypto,		//gcry_cipher_hd_t h
			out_buffer, //unsigned char *out
			out_size,	//size_t out_size
			in_buffer,	//const unsigned char *in
			1024);		//size_t inlen

		if (gcryErr)
		{
			printf("%s: %s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
			exit(0);
		}
		else
		{
			writeret = send(sockfd, out_buffer, readret + 16, 0);
			if (writeret <= 0)
			{
				perror("sent error in phrase 2");
				exit(0);
			}
			else
			{
				printf("wrote %d bytes\n", writeret);
				hmac(out_buffer, 1040, mac_key, 32, mac_buffer);
			}

			total_size += readret + 16;
		}
	}

	fprintf(stderr, "mac tag: %s", mac_buffer);

	//phrase 3: end of transmission
	char *trans_complete = "transmissioncompleted";
	send(sockfd, trans_complete, strlen(trans_complete), 0);

	printf("Successfully encrypted file %s to %s (%d bytes written.\n", filename, filename_suffix, total_size);
	printf("transmitting to %s.\n", address);
	printf("successfully transmitted %d bytes.\n", total_size);

	close(sockfd);

	//Close the file
	fclose(in);
	free(in_buffer);

	//Close the crypto handler
	gcry_cipher_close(crypto);
}