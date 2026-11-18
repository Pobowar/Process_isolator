/*
 * a2_revshell.c - Attack A2: reverse-shell-style chain on loopback
 *
 * Pattern: socket(AF_INET) → connect(127.0.0.1) → dup2 ×3 → execve /bin/sh
 * Where a real payload would open a reverse shell, we use /bin/true.
 *
 * Expected layer:  policy at socket (first call in the chain)
 * Expected result: chain stops at the first call; subsequent steps never run
 *
 * With --audit: the whole chain is logged but allowed.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    printf("[A2] reverse-shell chain starting\n");

    /* Step 1: open INET socket — should be DENIED here */
    errno = 0;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[A2] RESULT: chain stopped at socket — %s (errno=%d)\n",
               strerror(errno), errno);
        return 0; /* expected */
    }
    printf("[A2] socket succeeded (fd=%d), continuing chain...\n", sock);

    /* Step 2: connect to loopback:4444 */
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = __builtin_bswap16(4444);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    errno = 0;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        printf("[A2] connect failed: %s (errno=%d)\n",
               strerror(errno), errno);
        close(sock);
        return 1;
    }
    printf("[A2] connect succeeded — dup2 and exec following\n");

    /* Step 3: redirect stdin/stdout/stderr over the socket */
    dup2(sock, 0);
    dup2(sock, 1);
    dup2(sock, 2);
    close(sock);

    /* Step 4: exec a shell (we use /bin/true instead of /bin/sh) */
    execl("/bin/true", "/bin/true", (char *)NULL);
    perror("execl");
    return 1;
}
