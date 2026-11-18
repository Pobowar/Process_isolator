#include "define.h"

void setup_cgroup(void);
void attach_cgroup(pid_t pid);
void destroy_cgroup(void);
int evaluate(pid_t pid, long tag, struct user_regs_struct *reg,
             const char *sys_name, int *violation_count);
void logger_init(const char *filename);
void logger_log_event(pid_t pid, const char *sys_name, long tag, int denied);
void logger_exit_summary(int status, int total_violations);

void describe_status(int status, int verbose) {
  if (!verbose)
    return;
  if (WIFSTOPPED(status)) {
    int sig_num = WSTOPSIG(status);
    fprintf(stderr, "Stopped by signal %d (%s)", sig_num, strsignal(sig_num));
    int event = (status >> 16) & 0xffff;
    if (event == PTRACE_EVENT_SECCOMP) {
      fprintf(stderr, " [PTRACE_EVENT_SECCOMP]");
    }
  } else if (WIFEXITED(status)) {
    fprintf(stderr, "Exited with status %d", WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    fprintf(stderr, "Terminated by signal %d", WTERMSIG(status));
  }
  fprintf(stderr, "\n");
}

int child_helper(void *arg) {
  child_cfg_t *cfg = (child_cfg_t *)arg;

  // Set up namespaces, maps, rootfs here...
  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
    _exit(127);
  }
  raise(SIGSTOP);
  seccompp_filter_start();

  char *target_arg[] = {(char *)cfg->target, NULL};
  execvp(target_arg[0], target_arg);
  _exit(127);
}

int ptrace_main(int argc, char *argv[]) {
  child_cfg_t cfg = {.uid = 1000,
                     .gid = 1000,
                     .rootfs = "./rootfs",
                     .target = "./test",
                     .log_file = NULL,
                     .verbose = 1};

  // Parse command line flags (--rootfs, --log, --audit, -v) if needed
  logger_init(cfg.log_file);
  setup_cgroup();

  char *stack = malloc(STACK_SIZE);
  if (!stack) {
    perror("Stack allocation failed");
    exit(EXIT_FAILURE);
  }
  char *stack_top = stack + STACK_SIZE;

  pid_t process_pid =
      clone(child_helper, stack_top,
            CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | SIGCHLD,
            &cfg);
  if (process_pid < 0) {
    perror("Clone failed");
    free(stack);
    exit(EXIT_FAILURE);
  }

  int status = 0;
  pid_t wait_pid = waitpid(process_pid, &status, 0);
  if (wait_pid < 0 || !WIFSTOPPED(status)) {
    fprintf(stderr, "Child failed to stop initially\n");
    exit(EXIT_FAILURE);
  }

  // Attach child to cgroup while parked
  attach_cgroup(process_pid);

  PTRACE_CHECK(
      PTRACE_SETOPTIONS, process_pid, 0,
      (void *)(PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC));

  int signal = 0;
  int violation_count = 0;
  int final_exit_status = 0;

  while (1) {
    PTRACE_CHECK(PTRACE_CONT, process_pid, NULL, (void *)(long)signal);
    signal = 0;

    do {
      wait_pid = waitpid(process_pid, &status, 0);
    } while (wait_pid < 0 && errno == EINTR);

    if (wait_pid < 0) {
      if (errno == ECHILD)
        break;
      break;
    }

    describe_status(status, cfg.verbose);

    if (WIFEXITED(status)) {
      final_exit_status = WEXITSTATUS(status);
      break;
    }
    if (WIFSIGNALED(status)) {
      final_exit_status = 128 + WTERMSIG(status);
      break;
    }

    if (WIFSTOPPED(status)) {
      int event = (status >> 16) & 0xffff;
      if (event == 0) {
        signal = WSTOPSIG(status);
      }

      if (event == TAG_PRIV || event == PTRACE_EVENT_SECCOMP) {
        long tag = 0;
        PTRACE_CHECK(PTRACE_GETEVENTMSG, process_pid, NULL, &tag);

        struct user_regs_struct reg;
        PTRACE_CHECK(PTRACE_GETREGS, process_pid, NULL, &reg);

        char *sys_name =
            seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, reg.orig_rax);

        int denied =
            evaluate(process_pid, tag, &reg, sys_name, &violation_count);
        logger_log_event(process_pid, sys_name, tag, denied);

        if (sys_name)
          free(sys_name);
      }
    }
  }

  logger_exit_summary(final_exit_status, violation_count);
  destroy_cgroup();
  free(stack);

  return final_exit_status; // Return child's exit status instead of
                            // exit(EXIT_SUCCESS)
}

int main(int argc, char *argv[]) { return ptrace_main(argc, argv); }
