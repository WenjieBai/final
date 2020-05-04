#include <stdio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int main()
{
    char *ip = "192.168.15.5";
    char *port = "8081";
    printf("ip: %s port: %d\n", ip, atoi(port));

    //create socket struct
    struct sockaddr_in decryption_side;
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    //setup
    decryption_side.sin_family = AF_INET;
    decryption_side.sin_addr.s_addr = inet_addr(ip);
    decryption_side.sin_port = htons(atoi(port));

    //connect
    if (connect(sock, (struct sockaddr *)&decryption_side, sizeof(decryption_side)) < 0)
    {
        perror("connect error\n");
        exit(0);
    }

    //phrase 1: send filename and initlization vector
    int sendret;
    char *hello = "come on";
    int ret = write(sock, hello, 7);
    printf("ret %d", ret);
    return 0;
}