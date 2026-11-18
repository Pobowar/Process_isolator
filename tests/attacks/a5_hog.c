/*
 * a5_hog.c - Attack A5: memory hog + fork bomb
 *
 * Expected layer:  cgroup v2 (memory.max, pids.max)
 * Expected result: process stopped by OOM killer; oom_kill counter increments;
 *                  sandbox exit summary shows oom_kill > 0
 *
 * Report Table II row A5:
 *   Pattern: memory hog, fork bomb
 *   Layer:   cgroup limits
 *   Result:  stopped, oom_kill rises
 *
 * NOTE: requires cgroup v2 and sandbox run as root (or delegated cgroup).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHUNK_MB    8               /* allocate 8 MiB per step */
#define CHUNK_SIZE  (CHUNK_MB * 1024 * 1024)

int main(void) {
    printf("[A5] memory hog + fork bomb starting\n");
    printf("[A5] cgroup limit is 512 MiB — allocating until killed\n");

    /* Phase 1: allocate memory in 8 MiB chunks and touch each page */
    long total_mb = 0;
    for (;;) {
        char *p = malloc(CHUNK_SIZE);
        if (!p) {
            printf("[A5] malloc failed at %ld MiB — OOM at userspace level\n",
                   total_mb);
            break;
        }
        /* Touch every page to force kernel to actually map it */
        memset(p, 0xDE, CHUNK_SIZE);
        total_mb += CHUNK_MB;
        if (total_mb % 64 == 0)
            printf("[A5] allocated %ld MiB so far...\n", total_mb);
    }

    /* Phase 2: fork bomb to hit pids.max (default: 64) */
    printf("[A5] starting fork bomb\n");
    for (int i = 0; i < 200; i++) {
        pid_t p = fork();
        if (p < 0) {
            printf("[A5] fork() denied at iteration %d\n", i);
            break;
        }
        if (p == 0) {
            /* child sleeps so parent sees pids pile up */
            sleep(30);
            _exit(0);
        }
    }

    /* Reap any children we managed to fork */
    while (wait(NULL) > 0)
        ;

    printf("[A5] ERROR — process not killed by cgroup (is cgroup v2 active?)\n");
    return 1;
}
