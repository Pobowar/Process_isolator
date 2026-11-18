/*
 * writer.c - write-open test target
 *
 * Expected behaviour under sandbox:
 *   - open() with O_WRONLY|O_CREAT is denied with EPERM (policy: write-open)
 *   - Log contains a JSON line: verdict=deny, syscall=open/openat, reason=write-open
 *   - Program prints the errno it received
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    /* Attempt 1: open with O_WRONLY | O_CREAT */
    errno = 0;
    int fd = open("/tmp/sandbox_write_test.txt", O_WRONLY | O_CREAT, 0644);
    if (fd < 0) {
        printf("open(O_WRONLY|O_CREAT) failed: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("open(O_WRONLY|O_CREAT) unexpectedly succeeded, fd=%d\n", fd);
        close(fd);
    }

    /* Attempt 2: open with O_RDWR */
    errno = 0;
    fd = open("/tmp/sandbox_rdwr_test.txt", O_RDWR | O_CREAT, 0644);
    if (fd < 0) {
        printf("open(O_RDWR|O_CREAT) failed: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("open(O_RDWR|O_CREAT) unexpectedly succeeded, fd=%d\n", fd);
        close(fd);
    }

    /* Attempt 3: read-only open (should be ALLOWED) */
    errno = 0;
    fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) {
        printf("open(O_RDONLY) failed: %s (errno=%d)\n",
               strerror(errno), errno);
    } else {
        printf("open(O_RDONLY) allowed, fd=%d\n", fd);
        close(fd);
    }

    return 0;
}
