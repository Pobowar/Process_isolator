#include "define.h"

static void deny_syscall(pid_t pid, struct user_regs_struct *reg) {
  reg->orig_rax = -1;
  reg->rax = -EPERM;
  PTRACE_CHECK(PTRACE_SETREGS, pid, NULL, reg);
}

int evaluate(pid_t pid, long tag, struct user_regs_struct *reg,
             const char *sys_name, int *violation_count) {
  // Deny write and opens based on flags argument
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
      deny_syscall(pid, reg);
      return 1; // Denied
    }
  }

  // Deny socket unless domain (arg 0) is AF_UNIX
  if (tag == TAG_NET && strcmp(sys_name, "socket") == 0) {
    long domain = reg->rdi; // arg 0
    if (domain != AF_UNIX) {
      deny_syscall(pid, reg);
      return 1;
    }
  }

  // Deny privileged and restricted calls with EPERM, kill process after 3
  // violations
  if (tag == TAG_PRIV) {
    deny_syscall(pid, reg);
    (*violation_count)++;
    if (*violation_count >= 3) {
      fprintf(stderr,
              "[!] Violation threshold reached. Killing tracee PID %d\n", pid);
      ptrace(PTRACE_KILL, pid, NULL, NULL);
    }
    return 1;
  }

  // 4. Log execve
  if (tag == TAG_EXEC) {
    return 0; // Allowed
  }

  return 0;
}
