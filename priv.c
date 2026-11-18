/*
 * priv.c - privileged syscall probe
 *
 * Attempts several privileged syscalls that are on the PRIV watch list.
 * Policy: deny with EPERM, kill on the 3rd violation.
 *
 * Expected behaviour under sandbox:
 *   - Each call returns EPERM (or the process is killed on the 3rd)
 *   - Log shows verdict=deny for each, then verdict=kill
 *   - Supervisor kills the process after 3 priv violations
 */

#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

static void try_syscall(const char *name, int result) {
    if (result < 0)
        printf("%s failed: %s (errno=%d)\n", name, strerror(errno), errno);
    else
        printf("%s unexpectedly succeeded\n", name);
}

int main(void) {
    printf("priv_probe: starting privileged syscall attempts\n");

    /* Attempt 1: mount (PRIV → deny, priv_count=1) */
    errno = 0;
    try_syscall("mount", mount(NULL, "/tmp", "tmpfs", 0, NULL));

    /* Attempt 2: unshare (PRIV → deny, priv_count=2) */
    errno = 0;
    try_syscall("unshare(CLONE_NEWNET)", unshare(CLONE_NEWNET));

    /* Attempt 3: ptrace self (PRIV → kill, priv_count=3)
     * The process should be killed by SIGKILL before this printf runs. */
    errno = 0;
    try_syscall("ptrace(PTRACE_TRACEME)",
                (int)ptrace(PTRACE_TRACEME, 0, NULL, NULL));

    /* Should never reach here */
    printf("priv_probe: ERROR — still alive after 3 violations!\n");
    return 1;
}
