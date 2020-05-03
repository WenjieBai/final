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

	int i;

	for (i = 0; i < len; ++i)
	{
		s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	s[len] = 0;
}

int main(int argc, char *argv[])
{
	const int allow_debug_info = 0;

	int local_mode;
	char *filename = malloc(20);
	char *filename_suffix = malloc(23);
	char *argument = malloc(4);
	int total_size = 0;
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
		filename = argv[1];

		//Pull argument
		argument = argv[2];

		//Set proper mode
		local_mode = (!strcmp(argument, "-d")) ? 0 : 1;

		//Get ip and port
		char *address = argv[3];

		ip = strtok(address, ":");
		port = strtok(NULL, ":");

		if (allow_debug_info)
		{
			printf("ip: %s port: %d\n", ip, atoi(port));
		}

		//Set new filename if local_mode mode
		if (local_mode)
		{
			strcpy(filename_suffix, filename);
			strcat(filename_suffix, ".pur");
		}
	}

	//enter password
	char password[16];
	printf("Input password: ");
	fgets(password, sizeof password, stdin);

	//Hash the PW
	char *key[32];
	unsigned int keyLength = 32;
	char *salt[32];
	unsigned int saltLength = 32;

	//Hash the Password
	gcry_error_t gcryErr =
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

	if (gcryErr)
	{
		printf("Error.\n");
	}
	else if (allow_debug_info)
	{
		printf("Password hashed\n");
	}

	//Create crypto handler
	gcry_cipher_hd_t crypto;

	gcryErr =
		gcry_cipher_open(
			&crypto,
			GCRY_CIPHER_AES256,
			GCRY_CIPHER_MODE_ECB,
			0);

	if (gcryErr)
	{
		printf("%s: %s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
		return 1;
	}
	else if (allow_debug_info)
	{
		printf("Handler created.\n");
	}

	/*
	 *set cipher key
	 */
	gcryErr = gcry_cipher_setkey(crypto, key, keyLength);
	if (gcryErr)
	{
		printf("%s: %s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
		return 1;
	}
	else if (allow_debug_info)
	{
		printf("Key set.\n");
	}

	// generate IV
	size_t vector_len = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	char *vector = malloc(vector_len);
	gen_random(vector, vector_len);
	gcryErr = gcry_cipher_setiv(crypto, vector, vector_len);
	// printf("vec len %d\n", vector_len);

	if (gcryErr)
	{
		printf("%s: %s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
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
	in = fopen(filename, "r");
	if (local_mode)
	{
		if (out = fopen(filename_suffix, "r"))
		{
			printf("File %s already exists. Exiting.\n", filename_suffix);
			return 1;
		}
		else
		{
			out = fopen(filename_suffix, "w");
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
		while (readret = fread(buffer, 1, 1024, in))
		{
			//Buffer for encrypted data
			size_t out_size = readret + 1024;
			char *out_buffer = malloc(readret + 1024);

			//Encrypt the data
			gcryErr = gcry_cipher_encrypt(
				crypto,		//gcry_cipher_hd_t h
				out_buffer, //unsigned char *out
				out_size,	//size_t out_size
				buffer,		//const unsigned char *in
				1024);		//size_t inlen

			if (gcryErr)
			{
				printf("%s: %s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
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
			perror("connect error\n");
			exit(0);
		}

		//phrase 1: send initlization vector
		int sendret = send(sock, vector, vector_len, 0);
		if (sendret < 0)
		{
			perror("phrase 1 error");
		}

		//phrase 2: send encrypted data
		int readret ;
		while ((readret = fread(buffer, 1, 1024, in)) > 0)
		{
			
			printf("read %d bytes, ", readret);
			
			//Buffer for encrypted data
			size_t out_size = readret + 1024;
			char *out_buffer = malloc(out_size);

			//encryption
			gcryErr = gcry_cipher_encrypt(
				crypto,		//gcry_cipher_hd_t h
				out_buffer, //unsigned char *out
				out_size,	//size_t out_size
				buffer,		//const unsigned char *in
				1024);		//size_t inlen

			if (gcryErr)
			{
				printf("%s: %s\n", gcry_strsource(gcryErr), gcry_strerror(gcryErr));
				return 1;
			}
			else
			{
				int sendret = send(sock, out_buffer, readret + 16, 0);
				if (sendret < 0)
				{
					perror("sent error in phrase 2");
				}
				else
				{
					printf("wrote %d bytes\n", sendret);
				}

				total_size += readret + 16;
			}

		}
		

		//Tell server the transfer is done
		char trans_complete[] = "transmissioncompleted";
		send(sock, trans_complete, strlen(trans_complete), 0);

		printf("Successfully encrypted file %s to %s (%d bytes written.\n", filename, filename_suffix, total_size);
		printf("transmitting to %s.\n", argv[3]);
		printf("successfully received.\n");

		close(sock);
	}

	//Close the file
	fclose(in);
	if (local_mode)
	{
		fclose(out);
	}

	//Close the crypto handler
	gcry_cipher_close(crypto);

	//Free memory
	free(buffer);

	return 0;
}