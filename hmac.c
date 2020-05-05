
#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "openssl/sha.h"

int hmac(
    const unsigned char *data, /* pointer to data stream        */
    int data_len,              /* length of data stream         */
    const unsigned char *key,  /* pointer to authentication key */
    int key_len,               /* length of authentication key  */
    char *output)
{
    unsigned char md_value[EVP_MAX_MD_SIZE]; //32 byte
    unsigned int md_len;

    HMAC(EVP_sha256(), key, key_len, data, data_len, md_value, &md_len);

    memcpy(output, md_value, md_len);

    return 1;
}

int main()
{
    char *data = "1234";
    char *key = "key";
    char *output = malloc(10);
    hmac(data, 4, key, 3, output);
    printf("output %s", output);
}