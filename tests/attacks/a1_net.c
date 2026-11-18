/*
 * a1_net.c - Attack A1: socket(AF_INET) to reach the network
 *
 * Expected layer:  policy (scalar rule) + network namespace
 * Expected result: denied EPERM; JSON log line with verdict=deny
 *
 * Report Table II row A1:
 *   Pattern: socket(AF_INET) to reach the network
 *   Layer:   policy, netns
 *   Result:  denied, EPERM
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    printf("[A1] attempting socket(AF_INET, SOCK_STREAM, 0)\n");

    errno = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("[A1] RESULT: denied — %s (errno=%d)\n",
               strerror(errno), errno);
        return 0; /* expected */
    }

    /* If we got the socket, try a connect to prove network access */
    printf("[A1] WARNING: socket succeeded (fd=%d) — network not blocked!\n", fd);
    close(fd);
    return 1;
}
