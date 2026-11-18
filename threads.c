/*
 * threads.c - multi-thread open test target
 *
 * Spawns 4 worker threads; each opens a file 5 times (read-only).
 * Total watched FILE events: 4 threads × 5 opens = 20.
 *
 * Expected behaviour under sandbox:
 *   - 20 openat events across 4 distinct thread ids
 *   - All opens are read-only → all ALLOWED
 *   - Log lines show different tid values for each thread
 *   - No hangs across 200 stress runs
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define NUM_THREADS  4
#define OPENS_EACH   5
#define TARGET_FILE  "/etc/hostname"

static void *worker(void *arg) {
    int id = *(int *)arg;
    for (int i = 0; i < OPENS_EACH; i++) {
        int fd = open(TARGET_FILE, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "thread %d open #%d failed: %s\n",
                    id, i, strerror(errno));
        } else {
            close(fd);
        }
    }
    printf("thread %d done (%d opens)\n", id, OPENS_EACH);
    return NULL;
}

int main(void) {
    pthread_t threads[NUM_THREADS];
    int ids[NUM_THREADS];

    printf("threads: launching %d threads, %d opens each\n",
           NUM_THREADS, OPENS_EACH);

    for (int i = 0; i < NUM_THREADS; i++) {
        ids[i] = i;
        if (pthread_create(&threads[i], NULL, worker, &ids[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }

    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    printf("threads: all done, expected %d FILE events\n",
           NUM_THREADS * OPENS_EACH);
    return 0;
}
