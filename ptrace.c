

#include "define.h"

void setup_cgroup(void);
void attach_cgroup(pid_t pid);
void destroy_cgroup(void);
int evaluate(pid_t tid, pid_t first, long tag, struct user_regs_struct *reg,
             const char *sys_name, policy_state_t *state,
             int unsafe_path_policy);
void logger_init(const char *filename);
void logger_log_event(pid_t pid, const char *sys_name, long tag, int denied);
void logger_exit_summary(int status, int total_violations);

int tid_contains(tid_set_t *set, pid_t tid) {
  for (int i = 0; i < set->count; i++) {
    if (set->tids[i] == tid)
      return 1;
  }
  return 0;
}

void tid_add(tid_set_t *set, pid_t tid) {
  if (set->count < MAX_TIDS && !tid_contains(set, tid)) {
    set->tids[set->count++] = tid;
  }
}

void tid_remove(tid_set_t *set, pid_t tid) {
  for (int i = 0; i < set->count; i++) {
    if (set->tids[i] == tid) {
      set->tids[i] = set->tids[--set->count];
      break;
    }
  }
}
int run_multi(pid_t first, child_cfg_t *cfg) {
  tid_set_t alive = {0};
  tid_set_t expect_stop = {0};
  tid_set_t early_stop = {0};

  // Add the root leader to alive
  tid_add(&alive, first);

  policy_state_t state = {0};
  int status = 0;
  int final_exit_status = 0;

  // 1. Resume the first tracee since its initial SIGSTOP was consumed by
  // ptrace_main
  PTRACE_CHECK(PTRACE_CONT, first, NULL, NULL);

  while (alive.count > 0) {
    pid_t tid;
    do {
      tid = waitpid(-1, &status, __WALL);
    } while (tid < 0 && errno == EINTR);

    if (tid < 0) {
      if (errno == ECHILD)
        break;
      perror("waitpid multi");
      break;
    }

    // 2. Handle early stops: if a new thread's SIGSTOP arrives before the clone
    // event
    if (!tid_contains(&alive, tid)) {
      tid_add(&alive, tid);
      tid_add(&early_stop, tid);
    }

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      if (tid == first) {
        if (WIFEXITED(status)) {
          final_exit_status = WEXITSTATUS(status);
        } else {
          final_exit_status = 128 + WTERMSIG(status);
        }
      }
      tid_remove(&alive, tid);
      tid_remove(&expect_stop, tid);
      tid_remove(&early_stop, tid);
      continue;
    }

    if (WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);
      int event = (status >> 16) & 0xffff;

      // Swallow initial SIGSTOP for newly discovered tracees (normal or early
      // stop)
      if (sig == SIGSTOP) {
        if (tid_contains(&expect_stop, tid)) {
          tid_remove(&expect_stop, tid);
          if (cfg->race_delay > 0)
            usleep(cfg->race_delay);
          PTRACE_CHECK(PTRACE_CONT, tid, NULL, NULL);
          continue;
        }
        if (tid_contains(&early_stop, tid)) {
          tid_remove(&early_stop, tid);
          if (cfg->race_delay > 0)
            usleep(cfg->race_delay);
          PTRACE_CHECK(PTRACE_CONT, tid, NULL, NULL);
          continue;
        }
      }

      // Capture spawned child/thread IDs from clone/fork events
      if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
          event == PTRACE_EVENT_CLONE) {
        unsigned long new_tid = 0;
        PTRACE_CHECK(PTRACE_GETEVENTMSG, tid, NULL, &new_tid);

        // If the new thread already stopped early, consume it from early_stop;
        // otherwise, expect its initial SIGSTOP to arrive soon.
        if (tid_contains(&early_stop, (pid_t)new_tid)) {
          tid_remove(&early_stop, (pid_t)new_tid);
          tid_add(&alive, (pid_t)new_tid);
        } else {
          tid_add(&alive, (pid_t)new_tid);
          tid_add(&expect_stop, (pid_t)new_tid);
        }
      }

      if (event == PTRACE_EVENT_SECCOMP) {
        long tag = 0;
        PTRACE_CHECK(PTRACE_GETEVENTMSG, tid, NULL, &tag);

        struct user_regs_struct reg;
        PTRACE_CHECK(PTRACE_GETREGS, tid, NULL, &reg);

        char *sys_name =
            seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, reg.orig_rax);
        int denied = evaluate(tid, first, tag, &reg, sys_name, &state,
                              cfg->unsafe_path_policy);
        logger_log_event(tid, sys_name, tag, denied);

        if (sys_name)
          free(sys_name);
      }

      int forward_sig = (event == 0) ? sig : 0;
      if (cfg->race_delay > 0)
        usleep(cfg->race_delay);
      PTRACE_CHECK(PTRACE_CONT, tid, NULL, (void *)(long)forward_sig);
    }
  }
  return final_exit_status;
}

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
  (void)argc;
  (void)argv;
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

  PTRACE_CHECK(PTRACE_SETOPTIONS, process_pid, 0,
               (void *)(PTRACE_O_EXITKILL | PTRACE_O_TRACESECCOMP |
                        PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE |
                        PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK));

  // run_multi will handle all the tracee now
  return run_multi(process_pid, &cfg);
}

int main(int argc, char *argv[]) { return ptrace_main(argc, argv); }
