/*
 * net.c - network socket test target
 *
 * Expected behaviour under sandbox:
 *   - socket(AF_INET, ...) is DENIED with EPERM (policy: domain is not AF_UNIX)
 *   - socket(AF_UNIX, ...) is ALLOWED (benign)
 *   - Log shows first call denied, second allowed
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    /* Attempt 1: AF_INET socket - should be DENIED */
    errno = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket(AF_INET) denied: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("socket(AF_INET) unexpectedly succeeded, fd=%d\n", fd);
        close(fd);
    }

    /* Attempt 2: AF_UNIX socket - should be ALLOWED */
    errno = 0;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket(AF_UNIX) failed: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("socket(AF_UNIX) allowed, fd=%d\n", fd);
        close(fd);
    }

    /* Attempt 3: AF_INET6 socket - should also be DENIED */
    errno = 0;
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("socket(AF_INET6) denied: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("socket(AF_INET6) unexpectedly succeeded, fd=%d\n", fd);
        close(fd);
    }

    return 0;
}
