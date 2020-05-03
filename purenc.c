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

void gen_random(char *s, const int len)
{
	static const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
	srand(time(0));

	for (int i = 0; i < len; ++i)
	{
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

int main(int argc, char *argv[])
{
	const int allow_debug_info = 0;

	int local_mode;
	char *file = malloc(20);
	char *destFile = malloc(23);
	char *argument = malloc(4);
	char *dest = malloc(16);
	int totalSent = 0;
	char *ip;
	char *port;

	if (argc <= 2)
	{
		printf("\n\nUsage: uoenc <input file> [-d <output IP-addr:port>] [-l] (One argument required)\n");
		return 1;
	}
	else
	{
		//Pull input file out of args
		file = argv[1];

		//Pull argument
		argument = argv[2];

		//Set proper mode
		local_mode = (!strcmp(argument, "-d")) ? 0 : 1;

		//Get ip and port
		char *combined = argv[3];

		ip = strtok(combined, ":");
		port = strtok(NULL, ":");

		if (allow_debug_info)
		{
			printf("ip: %s port: %d\n", ip, atoi(port));
		}

		//Set new filename if local_mode mode
		if (local_mode)
		{
			strcpy(destFile, file);
			strcat(destFile, ".pur");
		}
	}

	//Prompt user for PW
	char password[128];
	printf("Password: ");
	fgets(password, sizeof password, stdin);

	//Hash the PW
	char *key[32];
	unsigned int keyLength = 32;
	char *salt[32];
	unsigned int saltLength = 32;

	//Hash the Password
	gcry_error_t cryptoError =
		gcry_kdf_derive(
			password,
			strlen(password),
			GCRY_KDF_PBKDF2,
			GCRY_CIPHER_AES256,
			password,
			strlen(password),
			1024,
			keyLength,
			key);

	if (cryptoError)
	{
		printf("Error.\n");
	}
	else if (allow_debug_info)
	{
		printf("Password hashed\n");
	}

	//Create crypto handler
	gcry_cipher_hd_t crypto;

	cryptoError =
		gcry_cipher_open(
			&crypto,
			GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_ECB,
			0);

	if (cryptoError)
	{
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}
	else if (allow_debug_info)
	{
		printf("Handler created.\n");
	}

	/*
	 *set cipher key
	 */
	cryptoError = gcry_cipher_setkey(crypto, key, keyLength);
	if (cryptoError)
	{
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}
	else if (allow_debug_info)
	{
		printf("Key set.\n");
	}

	/*
	 * Initialize the vector(???)
	 */
	char *vector = malloc(1024);
	gen_random(vector, sizeof(vector));
	size_t vector_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	cryptoError = gcry_cipher_setiv(crypto, vector, vector_len);
	printf("vec len %d\n", vector_len);

	if (cryptoError)
	{
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}
	else if (allow_debug_info)
	{
		printf("IV Set.\n");
	}

	//Create file handler and file buffer
	FILE *in;
	FILE *out;

	//Open the file
	in = fopen(file, "r");
	if (local_mode)
	{
		if (out = fopen(destFile, "r"))
		{
			printf("File %s already exists. Exiting.\n", destFile);
			return 1;
		}
		else
		{
			out = fopen(destFile, "w");
		}
	}

	//Error detection
	if (in == NULL || (out == NULL && local_mode))
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
		return 1;
	}
	else if (allow_debug_info)
	{
		printf("Files opened.\n");
	}

	//Print file contents to another file
	int readret;
	int total = 0;
	char *buffer = malloc(1024);

	if (local_mode)
	{
		while (readret = readret(buffer, 1, 1024, in))
		{
			//Buffer for encrypted data
			size_t out_size = readret + 1024;
			char *out_buffer = malloc(readret + 1024);

			//Encrypt the data
			cryptoError = gcry_cipher_encrypt(
				crypto,		//gcry_cipher_hd_t h
				out_buffer, //unsigned char *out
				out_size,	//size_t out_size
				buffer,		//const unsigned char *in
				1024);		//size_t inlen

			if (cryptoError)
			{
				printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
				return 1;
			}
			else
			{
				fwrite(out_buffer, readret + 16, 1, out);
				printf("Read %d bytes of data. Writing %i bytes of Data.\n", readret, readret + 16);
			}

			free(out_buffer);
		}
	}
	else
	{
		if (allow_debug_info)
		{
			printf("Configuring networking.\n");
		}

		//Set incoming buffer & size
		char netInBuffer[1041];
		int netInLength;
		if (allow_debug_info)
		{
			printf("Buffer created.\n");
		}

		//Create socket
		int sock;
		if (allow_debug_info)
		{
			printf("Socket created.\n");
		}

		//Create socket struct
		struct sockaddr_in server;
		if (allow_debug_info)
		{
			printf("Structs created.\n");
		}

		//bind
		sock = socket(AF_INET, SOCK_STREAM, 0);
		if (allow_debug_info)
		{
			printf("Socket created.\n");
		}

		//setup
		server.sin_family = AF_INET;
		server.sin_addr.s_addr = inet_addr(ip);
		server.sin_port = htons(atoi(port));

		//connect
		if (connect(sock, (struct sockaddr *)&server, sizeof(struct sockaddr)) == -1)
		{
			perror(stderr, "connect error");
			return 1;
		}

		//send initlization vector
		int sendret = send(sock, vector, vector_len, 0);

		//Recieve data
		netInLength = recv(sock, netInBuffer, 1040, 0);
		netInBuffer[netInLength] = '\0';

		if (!strcmp(netInBuffer, "PWD"))
		{
			while (readret = fread(buffer, 1, 1024, in))
			{
				if (readret == 0)
				{
					printf("CRASHING\n");
				}
				//Buffer for encrypted data
				size_t out_size = readret + 1024;
				char *out_buffer = malloc(readret + 1024);

				//Encrypt the data
				cryptoError = gcry_cipher_encrypt(
					crypto,		//gcry_cipher_hd_t h
					out_buffer, //unsigned char *out
					out_size,	//size_t out_size
					buffer,		//const unsigned char *in
					1024);		//size_t inlen

				if (cryptoError)
				{
					printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
					return 1;
				}
				else
				{
					send(sock, out_buffer, readret + 16, 0);
					printf("Read %d bytes of data. Transmitting %i bytes of Data.\n", readret, readret + 16);
					totalSent += readret + 16;
				}

				//free(out_buffer);
			}
			printf("Successfully transfered %d bytes.\n", totalSent);

			//Tell server the transfer is done
			char trans_complete[] = "transmissioncompleted";
			send(sock, trans_complete, strlen(trans_complete), 0);
		}

		close(sock);
	}

	//Close the file
	fclose(in);
	if (local_mode_mode)
	{
		fclose(out);
	}

	//Close the crypto handler
	gcry_cipher_close(crypto);

	//Free memory
	free(buffer);

	return 0;
}