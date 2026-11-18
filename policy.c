#include "define.h"

static void deny_syscall(pid_t pid, struct user_regs_struct *reg) {
  reg->orig_rax = -1;
  reg->rax = -EPERM;
  PTRACE_CHECK(PTRACE_SETREGS, pid, NULL, reg);
}

int evaluate(pid_t tid, pid_t first, long tag, struct user_regs_struct *reg,
             const char *sys_name, policy_state_t *state,
             int unsafe_path_policy) {

  (void)unsafe_path_policy;

  // Handle Privileged / Restricted Syscalls
  if (tag == TAG_PRIV) {
    deny_syscall(tid, reg);
    state->violation_count++;
    if (state->violation_count >= 3) {
      fprintf(stderr,
              "[!] Violation threshold reached. Killing target leader PID %d\n",
              first);
      kill(first, SIGKILL);
    }
    return 1;
  }

  // Handle Execution Allow first exec
  if (tag == TAG_EXEC) {
    state->exec_count++;
    return 0;
  }

  // Deny write opens based on flags argument
  if (tag == TAG_OPEN) {
    long flags = 0;
    if (strcmp(sys_name, "openat") == 0 || strcmp(sys_name, "openat2") == 0) {
      flags = reg->rdx; // arg 2
    } else if (strcmp(sys_name, "open") == 0) {
      flags = reg->rsi; // arg 1
    } else if (strcmp(sys_name, "creat") == 0) {
      flags = O_WRONLY | O_CREAT | O_TRUNC;
    }

    // Check if flags request writing
    if ((flags & O_ACCMODE) != O_RDONLY) {
      deny_syscall(tid, reg);
      return 1; // Denied
    }
  }

  // Deny socket unless domain (arg 0) is AF_UNIX (TAG_NET)
  if (tag == TAG_NET && strcmp(sys_name, "socket") == 0) {
    long domain = reg->rdi; // arg 0
    if (domain != AF_UNIX) {
      deny_syscall(tid, reg);
      return 1;
    }
  }

  return 0;
}
