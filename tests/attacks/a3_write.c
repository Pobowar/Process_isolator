/*
 * a3_write.c - Attack A3: open /etc/passwd for writing
 *
 * Expected layer:  policy (flags rule — O_WRONLY flag is a scalar)
 * Expected result: denied, path logged as advisory
 *
 * Report Table II row A3:
 *   Pattern: open /etc/passwd for writing
 *   Layer:   policy (flags)
 *   Result:  denied, path logged
 *
 * The deny is based on the O_WRONLY flag (scalar argument), NOT on the
 * path string — the path is only logged as advisory context (TOCTOU stance).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    printf("[A3] attempting to open /etc/passwd for writing\n");

    /* Attempt with O_WRONLY */
    errno = 0;
    int fd = open("/etc/passwd", O_WRONLY);
    if (fd < 0) {
        printf("[A3] RESULT: open(O_WRONLY) denied — %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("[A3] WARNING: open(O_WRONLY) succeeded! fd=%d\n", fd);
        close(fd);
    }

    /* Attempt with O_RDWR */
    errno = 0;
    fd = open("/etc/passwd", O_RDWR);
    if (fd < 0) {
        printf("[A3] RESULT: open(O_RDWR) denied — %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("[A3] WARNING: open(O_RDWR) succeeded! fd=%d\n", fd);
        close(fd);
    }

    /* Read-only should be allowed */
    errno = 0;
    fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        printf("[A3] open(O_RDONLY) also denied: %s\n", strerror(errno));
    } else {
        printf("[A3] open(O_RDONLY) allowed (expected) fd=%d\n", fd);
        close(fd);
    }

    return 0;
}
