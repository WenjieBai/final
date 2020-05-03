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

void localmode(char *argv);
void distantmode(char *argv);

int main(int argc, char *argv[])
{

	char *file = malloc(20);
	char *file_nosuffix = malloc(23);
	char password[16]; //Need in high scope
	FILE *out;		   //Always be used
	int mode;		   //Mode designator

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
			localmode(argv) :
		}
		else if (!strcmp(argv[1], "-d"))
		{
			distantmode(argv);
		}
		else
		{
			perror("argument can either be -l or -d\n");
			exit(0);
		}
	}
}

// void localmode(char *argv)
// {
// 	printf("local mode\n");
// 	//Get in file name from args
// 	file = argv[2];

// 	//Make sure the file is in the right .uo format
// 	if (file[strlen(file) - 1] == 'o' && file[strlen(file) - 2] == 'u' && file[strlen(file) - 3] == '.')
// 	{
// 		strcpy(file_nosuffix, file);
// 		file_nosuffix[strlen(file) - 1] = 0;
// 		file_nosuffix[strlen(file) - 2] = 0;
// 		file_nosuffix[strlen(file) - 3] = 0;
// 	}
// 	else
// 	{
// 		printf("\n\nIncorrect file format/extension.\n");
// 	}

// 	//Prompt user for PW
// 	printf("Input password: ");
// 	fgets(password, sizeof password, stdin);

// 	if (crypt_init(password))
// 	{
// 		printf("Error configuring libgcrypt.\n");
// 		return 1;
// 	}

// 	//Create file handler and file buffer
// 	FILE *in;

// 	//Open the file
// 	in = fopen(file, "r");
// 	out = fopen(file_nosuffix, "w");

// 	//File opening error detection
// 	if (in == NULL || out == NULL)
// 	{
// 		printf("Error opening ");
// 		if (in == NULL)
// 		{
// 			printf("in");
// 		}
// 		if (out == NULL)
// 		{
// 			printf("out");
// 		}
// 		printf(" file.\n");
// 	}


// 	//decrypt the data from file
// 	char *fileBuffer = malloc(2048);
// 	int fRead;

// 	while (fRead = fread(fileBuffer, 1, 1040, in))
// 	{
// 		//Buffer for unencrypted data
// 		size_t unOutSize = 2048;
// 		char *unOutBuffer = malloc(2048);

// 		if (!decrypt(crypto, unOutBuffer, unOutSize, fileBuffer, 2048))
// 		{
// 			printf("Read %d bytes of data. Writing %i bytes of Data.\n", fRead, fRead - 16);
// 			fwrite(unOutBuffer, fRead - 16, 1, out);
// 		}

// 		free(unOutBuffer);
// 	}

// 	//Close the file
// 	fclose(in);
// 	fclose(out);

// 	//Free memory
// 	free(fileBuffer);
// }

void distantmode(char *argv)
{
	printf("distant mode\n");
	int port = atoi(argv[2]);

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
	if (getsockname(new_sockfd, (struct sockaddr *)&encryption_side, &enc_len) == -1)
	{
		perror("getsockname error\n");
	}

	printf("connection from %s : %d", inet_ntoa(encryption_side.sin_addr), ntohs(encryption_side.sin_port));

	// phrase 1: receive filename and IV

	unsigned char[1040] buffer;
	memset(buffer, 0, sizeof(buffer));

	char *filename = malloc(20);
	char *filename_suffix = malloc(23);

	if(int recvret = recv(new_socketfd, filename_suffix, 16, 0) < 0)
	{
		perror("filename_suffix\n");
	}
	printf("file name %s\n"filename_suffix);


	int netInLength;
	int netOut;
	int total = 0;

	char *IV = malloc(16);
	int recvret = recv(new_socketfd, IV, 16, 0);
	IV[16] = '\0';

	printf("Inbount file. Password: ");
	fgets(password, sizeof password, stdin);

	//Configure glib and file handler
	crypt_init(password, IV);
	if (out = fopen(file_nosuffix, "r"))
	{
		printf("File %s already exists. Exiting.\n", file_nosuffix);
		return 1;
	}
	else
	{
		out = fopen(file_nosuffix, "w");
	}

	//phrase 2: receive encrypted data
	while (1)
	{
		netInLength = recv(new_socketfd, buffer, 1040, 0);
		buffer[netInLength + 1] = '\0';
		if (DEBUG)
		{
			printf("-->Recieved %d bytes of Data\n", netInLength);
		}
		if (DEBUG)
		{
			printf("%s (%d bytes)\n", buffer, netInLength);
		}

		//dencrypt the data
		size_t unOutSize = 2048;
		unsigned char *unOutBuffer = malloc(2048);

		if (netInLength > 0 && !decrypt(crypto, unOutBuffer, unOutSize, buffer, 2048))
		{
			if (DEBUG)
			{
				printf("Decrypted.\n");
			}
			if (netInLength < 1024)
			{
				unOutBuffer[netInLength - 19] = '\0';
				fwrite(unOutBuffer, netInLength - 19, 1, out);
				netOut = netInLength - 19;
			}
			else
			{
				unOutBuffer[netInLength - 16] = '\0';
				fwrite(unOutBuffer, netInLength - 16, 1, out);
				netOut = netInLength - 16;
			}
			fflush(out);
			printf("Recieved %d bytes of data. Writing %i bytes of Data.\n", netInLength, netOut);
			total += netOut;
		}

		free(unOutBuffer);

		if (netInLength < 1024)
		{
			printf("Transfer successful. %d bytes written.\n", total);
			break;
		}
	}
}

//Close the crypto handler
gcry_cipher_close(crypto);

return 0;
}

int decrypt(gcry_cipher_hd_t h, unsigned char *out, size_t outsize, unsigned char *in, size_t inlen)
{
	if (DEBUG)
	{
		printf("Method called successfully\n");
	}

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

int crypt_init(char *password, char *Init_vec)
{
	char *key[32];
	unsigned int keyLength = 32;

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
			keyLength,
			key);

	if (cryptoError)
	{
		printf("Error.\n");
	}
	else if (DEBUG)
	{
		printf("Password hashed\n");
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
		return 1;
	}
	else if (DEBUG)
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
	else if (DEBUG)
	{
		printf("Key set.\n");
	}

	/*
	 * Initialize the vector
	 */
	char *vector = "athenstiromni"; //TODO: Random init vector;
	size_t vLength = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	cryptoError =
		gcry_cipher_setiv(crypto, vector, vLength);

	if (cryptoError)
	{
		printf("%s: %s\n", gcry_strsource(cryptoError), gcry_strerror(cryptoError));
		return 1;
	}
	else if (DEBUG)
	{
		printf("IV Set.\n");
	}

	return 0;
}