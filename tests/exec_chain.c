/*
 * exec_chain.c - fork + exec chain test target
 *
 * Expected behaviour under sandbox:
 *   - Parent forks; child execs /bin/true
 *   - Both execve events are logged (first is the target itself, second is /bin/true)
 *   - Both are ALLOWED
 *   - Parent waits for child and prints its exit status
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    printf("exec_chain: parent pid=%d\n", (int)getpid());

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 1;
    }

    if (child == 0) {
        /* Child: exec /bin/true */
        printf("exec_chain: child pid=%d, execing /bin/true\n", (int)getpid());
        execl("/bin/true", "/bin/true", (char *)NULL);
        perror("execl");
        _exit(127);
    }

    /* Parent: wait for child */
    int status = 0;
    waitpid(child, &status, 0);
    if (WIFEXITED(status))
        printf("exec_chain: child exit=%d\n", WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        printf("exec_chain: child killed by signal %d\n", WTERMSIG(status));

    return 0;
}
