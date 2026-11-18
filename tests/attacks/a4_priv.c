/*
 * a4_priv.c - Attack A4: mount, unshare, chroot, ptrace privilege escalation
 *
 * Expected layer:  policy (PRIV tag) + kill on 3rd violation
 * Expected result: denied, then killed after 3 privileged syscall attempts
 *
 * Report Table II row A4:
 *   Pattern: mount, unshare, chroot, ptrace
 *   Layer:   policy, kill
 *   Result:  denied, then killed
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

static void attempt(const char *name, int result) {
    if (result < 0)
        printf("[A4] %s denied: %s (errno=%d)\n",
               name, strerror(errno), errno);
    else
        printf("[A4] %s unexpectedly succeeded\n", name);
}

int main(void) {
    printf("[A4] starting privilege escalation attempts\n");

    /* Violation 1: mount */
    errno = 0;
    attempt("mount(tmpfs)", mount("none", "/tmp", "tmpfs", 0, NULL));

    /* Violation 2: unshare(CLONE_NEWUSER) */
    errno = 0;
    attempt("unshare(CLONE_NEWUSER)", unshare(CLONE_NEWUSER));

    /* Violation 3: ptrace → triggers KILL (priv_count >= 3) */
    errno = 0;
    attempt("ptrace(PTRACE_TRACEME)",
            (int)ptrace(PTRACE_TRACEME, 0, NULL, NULL));

    /* Violation 4: chroot (should never be reached; process is dead) */
    errno = 0;
    attempt("chroot(/tmp)", chroot("/tmp"));

    printf("[A4] ERROR — process survived 3+ violations, kill did not fire!\n");
    return 1;
}
