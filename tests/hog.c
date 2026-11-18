/*
 * hog.c - memory hog / fork bomb test target
 *
 * Allocates memory in a tight loop until killed by the cgroup v2 memory limit.
 * Also forks repeatedly to hit the pids.max limit.
 *
 * Expected behaviour under sandbox:
 *   - Process is stopped/killed by cgroup (memory.max = 512 MiB, pids.max = 64)
 *   - oom_kill counter in memory.events increments
 *   - Sandbox exit summary shows oom_kill > 0
 *
 * NOTE: requires cgroup v2 to be active.
 *       Run: stat -fc %T /sys/fs/cgroup   (should print "cgroup2fs")
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define CHUNK_SIZE  (1024 * 1024)   /* 1 MiB per allocation */
#define MAX_CHUNKS  600             /* up to 600 MiB, cgroup limit is 512 MiB */

int main(void) {
    printf("hog: starting memory allocation (cgroup limit should stop me)\n");

    /* Phase 1: memory hog */
    for (int i = 0; i < MAX_CHUNKS; i++) {
        char *p = malloc(CHUNK_SIZE);
        if (!p) {
            printf("hog: malloc failed at chunk %d\n", i);
            break;
        }
        /* Touch every page so the kernel actually allocates it */
        memset(p, 0xAB, CHUNK_SIZE);
        if (i % 50 == 0)
            printf("hog: allocated %d MiB so far\n", i);
    }

    /* Phase 2: fork bomb (hits pids.max = 64) */
    printf("hog: starting fork bomb\n");
    for (int i = 0; i < 128; i++) {
        pid_t p = fork();
        if (p < 0) {
            printf("hog: fork failed at iteration %d\n", i);
            break;
        }
        if (p == 0) {
            /* child: sleep briefly and exit */
            sleep(10);
            _exit(0);
        }
    }

    /* Should never reach here cleanly */
    printf("hog: ERROR — still alive (cgroup did not kill?)\n");
    return 1;
}
