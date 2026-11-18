#include "define.h"

static int tid_contains(const tid_set_t *set, pid_t tid) {
  for (int i = 0; i < set->count; i++)
    if (set->tids[i] == tid)
      return 1;
  return 0;
}

static void tid_add(tid_set_t *set, pid_t tid) {
  if (set->count < MAX_TIDS && !tid_contains(set, tid))
    set->tids[set->count++] = tid;
}

static void tid_remove(tid_set_t *set, pid_t tid) {
  for (int i = 0; i < set->count; i++) {
    if (set->tids[i] == tid) {
      set->tids[i] = set->tids[--set->count];
      break;
    }
  }
}

static void resume(int request, pid_t tid, int sig) {
  errno = 0;
  if (ptrace(request, tid, NULL, (void *)(long)sig) == -1 && errno != ESRCH) {
    fprintf(stderr, "ptrace(resume, tid %d) failed: %s\n", tid,
            strerror(errno));
    exit(EXIT_FAILURE);
  }
}

static void describe_status(pid_t tid, int status, int verbose) {
  if (!verbose)
    return;
  fprintf(stderr, "[wait] tid %d: ", tid);
  if (WIFSTOPPED(status)) {
    int sig_num = WSTOPSIG(status);
    int event = (status >> 16) & 0xffff;
    if (sig_num == (SIGTRAP | 0x80))
      fprintf(stderr, "syscall stop");
    else if (event == PTRACE_EVENT_SECCOMP)
      fprintf(stderr, "event stop PTRACE_EVENT_SECCOMP");
    else if (event == PTRACE_EVENT_EXEC)
      fprintf(stderr, "event stop PTRACE_EVENT_EXEC");
    else if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK ||
             event == PTRACE_EVENT_VFORK)
      fprintf(stderr, "event stop clone/fork/vfork");
    else
      fprintf(stderr, "stopped by signal %d (%s)", sig_num, strsignal(sig_num));
  } else if (WIFEXITED(status)) {
    fprintf(stderr, "exited, code=%d", WEXITSTATUS(status));
  } else if (WIFSIGNALED(status)) {
    fprintf(stderr, "terminated by signal %d (%s)", WTERMSIG(status),
            strsignal(WTERMSIG(status)));
  }
  fprintf(stderr, "\n");
}

static void read_tracee_string(pid_t tid, unsigned long addr, char *buf,
                               size_t cap) {
  buf[0] = 0;
  char p[64];
  snprintf(p, sizeof p, "/proc/%d/mem", tid);
  int fd = open(p, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return;
  size_t got = 0;
  int found_nul = 0;
  while (got < cap - 1 && !found_nul) {
    size_t chunk = 4096 - ((addr + got) & 4095);
    if (chunk > cap - 1 - got)
      chunk = cap - 1 - got;
    ssize_t r = pread(fd, buf + got, chunk, (off_t)(addr + got));
    if (r <= 0)
      break;
    if (memchr(buf + got, 0, (size_t)r))
      found_nul = 1;
    got += (size_t)r;
  }
  buf[got] = 0;
  close(fd);
}

static int path_arg_index(const char *name) {
  if (!strcmp(name, "open") || !strcmp(name, "creat") ||
      !strcmp(name, "execve"))
    return 0;
  if (!strcmp(name, "openat") || !strcmp(name, "openat2") ||
      !strcmp(name, "execveat"))
    return 1;
  return -1;
}

static void get_args(const struct user_regs_struct *r, unsigned long a[6]) {
  a[0] = r->rdi;
  a[1] = r->rsi;
  a[2] = r->rdx;
  a[3] = r->r10;
  a[4] = r->r8;
  a[5] = r->r9;
}

static void deny_syscall(pid_t tid, struct user_regs_struct *reg, int err) {
  reg->orig_rax = (unsigned long long)-1;
  reg->rax = (unsigned long long)(-(long long)err);
  PTRACE_CHECK(PTRACE_SETREGS, tid, NULL, reg);
}

#define MAX_REC 512
static char *rec_names[MAX_REC];
static int n_rec;

static void record_add(const char *name) {
  for (int i = 0; i < n_rec; i++)
    if (strcmp(rec_names[i], name) == 0)
      return;
  if (n_rec < MAX_REC)
    rec_names[n_rec++] = strdup(name);
}

static int cmp_str(const void *a, const void *b) {
  return strcmp(*(char *const *)a, *(char *const *)b);
}

static void record_write(const char *file) {
  FILE *f = fopen(file, "w");
  if (!f) {
    fprintf(stderr, "cannot write %s: %s\n", file, strerror(errno));
    return;
  }
  qsort(rec_names, (size_t)n_rec, sizeof rec_names[0], cmp_str);
  for (int i = 0; i < n_rec; i++)
    fprintf(f, "%s\n", rec_names[i]);
  fclose(f);
  fprintf(stderr, "[record] %d distinct syscalls written to %s\n", n_rec, file);
}

typedef struct {
  pid_t tid;
  long nr;
  unsigned long args[6];
} inflight_t;
static inflight_t inflight[MAX_TIDS];
static int n_inflight;

static inflight_t *inflight_find(pid_t tid) {
  for (int i = 0; i < n_inflight; i++)
    if (inflight[i].tid == tid)
      return &inflight[i];
  return NULL;
}

static void inflight_drop(pid_t tid) {
  for (int i = 0; i < n_inflight; i++)
    if (inflight[i].tid == tid) {
      inflight[i] = inflight[--n_inflight];
      return;
    }
}

static void print_syscall_line(const inflight_t *f, long ret, int has_ret) {
  char *s = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)f->nr);
  fprintf(stderr, "[%d] %s(0x%lx, 0x%lx, 0x%lx, ...)", f->tid,
          s ? s : "unknown", f->args[0], f->args[1], f->args[2]);
  if (!has_ret)
    fprintf(stderr, " = ?\n");
  else if (ret < 0 && ret > -4096)
    fprintf(stderr, " = -1 (%s)\n", strerror((int)-ret));
  else
    fprintf(stderr, " = %ld\n", ret);
  free(s);
}

static void on_syscall_stop(pid_t tid, const child_cfg_t *cfg) {
  struct user_regs_struct r;
  PTRACE_CHECK(PTRACE_GETREGS, tid, NULL, &r);
  inflight_t *f = inflight_find(tid);
  if (!f) {
    if (n_inflight >= MAX_TIDS)
      return;
    f = &inflight[n_inflight++];
    f->tid = tid;
    f->nr = (long)r.orig_rax;
    get_args(&r, f->args);
    if (cfg->record_file) {
      char *s = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)f->nr);
      if (s)
        record_add(s);
      free(s);
    }
  } else {
    if (!cfg->record_file || cfg->verbose)
      print_syscall_line(f, (long)r.rax, 1);
    inflight_drop(tid);
  }
}

static int on_seccomp_stop(pid_t tid, pid_t first, const child_cfg_t *cfg,
                           policy_state_t *state) {
  unsigned long tag = 0;
  PTRACE_CHECK(PTRACE_GETEVENTMSG, tid, NULL, &tag);

  struct user_regs_struct reg;
  PTRACE_CHECK(PTRACE_GETREGS, tid, NULL, &reg);

  char *sys_name =
      seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, (int)reg.orig_rax);

  call_t c = {.name = sys_name ? sys_name : "UNKNOWN", .tag = (long)tag};
  get_args(&reg, c.args);

  char path[4096];
  if (sys_name && (tag == TAG_OPEN || tag == TAG_EXEC)) {
    int idx = path_arg_index(sys_name);
    if (idx >= 0) {
      read_tracee_string(tid, c.args[idx], path, sizeof path);
      c.path = path;
    }
  }

  verdict_t v =
      evaluate(&c, state, cfg->unsafe_path_policy, cfg->protected_path);
  int enforce = !cfg->audit;
  logger_log_event(tid, &c, &v, enforce);

  int killed = 0;
  if (enforce && v.action == ACT_DENY) {
    deny_syscall(tid, &reg, v.err);
  } else if (enforce && v.action == ACT_KILL) {
    fprintf(stderr, "[!] Violation threshold reached. Killing target PID %d\n",
            first);
    kill(first, SIGKILL);
    killed = 1;
  }

  if (!killed && cfg->race_delay > 0 && tag == TAG_OPEN)
    usleep((useconds_t)cfg->race_delay);

  free(sys_name);
  return killed;
}

static int run_multi(pid_t first, const child_cfg_t *cfg,
                     policy_state_t *state) {
  tid_set_t alive = {0};
  tid_set_t expect_stop = {0};
  tid_set_t early_stop = {0};

  int exit_code = 0;
  int status = 0;

  const int resume_req =
      cfg->mode == MODE_HYBRID ? PTRACE_CONT : PTRACE_SYSCALL;

  tid_add(&alive, first);

  resume(resume_req, first, 0);

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
    describe_status(tid, status, cfg->verbose);

    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      if (tid == first)
        exit_code =
            WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
      if (cfg->mode == MODE_TRACE) {
        inflight_t *f = inflight_find(tid);
        if (f && (!cfg->record_file || cfg->verbose))
          print_syscall_line(f, 0, 0);
        inflight_drop(tid);
      }
      tid_remove(&alive, tid);
      tid_remove(&expect_stop, tid);
      tid_remove(&early_stop, tid);
      continue;
    }
    if (!WIFSTOPPED(status))
      continue;

    if (!tid_contains(&alive, tid)) {
      tid_add(&early_stop, tid);
      continue;
    }

    const int sig = WSTOPSIG(status);
    const int event = (status >> 16) & 0xffff;

    if (event == 0 && sig == SIGSTOP && tid_contains(&expect_stop, tid)) {
      tid_remove(&expect_stop, tid);
      resume(resume_req, tid, 0);
      continue;
    }

    int inject = 0;
    int skip_resume = 0;

    if (sig == (SIGTRAP | 0x80)) {
      on_syscall_stop(tid, cfg);
    } else if (event != 0) {
      if (event == PTRACE_EVENT_CLONE || event == PTRACE_EVENT_FORK ||
          event == PTRACE_EVENT_VFORK) {
        unsigned long new_tid = 0;
        PTRACE_CHECK(PTRACE_GETEVENTMSG, tid, NULL, &new_tid);
        tid_add(&alive, (pid_t)new_tid);
        if (tid_contains(&early_stop, (pid_t)new_tid)) {
          tid_remove(&early_stop, (pid_t)new_tid);
          resume(resume_req, (pid_t)new_tid, 0);
        } else {
          tid_add(&expect_stop, (pid_t)new_tid);
        }
      } else if (event == PTRACE_EVENT_SECCOMP) {

        skip_resume = on_seccomp_stop(tid, first, cfg, state);
      }

    } else {
      inject = sig;
    }

    if (!skip_resume)
      resume(resume_req, tid, inject);
  }
  return exit_code;
}

static void child_die(const char *what) {
  fprintf(stderr, "sandbox(child): %s: %s\n", what, strerror(errno));
  _exit(126);
}

static void write_file_or_die(const char *path, const char *s) {
  int fd = open(path, O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    child_die(path);
  if (write(fd, s, strlen(s)) < 0)
    child_die(path);
  close(fd);
}

static void setup_user_ns(const child_cfg_t *cfg) {
  char map[64];
  snprintf(map, sizeof map, "0 %u 1", (unsigned)cfg->uid);
  write_file_or_die("/proc/self/uid_map", map);
  write_file_or_die("/proc/self/setgroups", "deny");
  snprintf(map, sizeof map, "0 %u 1", (unsigned)cfg->gid);
  write_file_or_die("/proc/self/gid_map", map);
}

static void setup_mounts(const child_cfg_t *cfg) {
  if (!cfg->rootfs)
    return;
  if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
    child_die("make mounts private");
  if (mount(cfg->rootfs, cfg->rootfs, NULL, MS_BIND | MS_REC, NULL) < 0)
    child_die("bind-mount rootfs onto itself");

  char proc_path[4096];
  snprintf(proc_path, sizeof proc_path, "%s/proc", cfg->rootfs);
  mkdir(proc_path, 0555);
  if (mount("proc", proc_path, "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) <
      0)
    fprintf(stderr, "sandbox(child): warning: cannot mount /proc: %s\n",
            strerror(errno));

  if (chdir(cfg->rootfs) < 0)
    child_die("chdir rootfs");
  if (mkdir(".old", 0700) < 0 && errno != EEXIST)
    child_die("mkdir .old");

  if (syscall(SYS_pivot_root, ".", ".old") == 0) {
    if (chdir("/") < 0)
      child_die("chdir /");
    umount2("/.old", MNT_DETACH);
    rmdir("/.old");
  } else {

    fprintf(stderr, "sandbox(child): pivot_root failed (%s), using chroot\n",
            strerror(errno));
    rmdir(".old");
    if (chroot(".") < 0)
      child_die("chroot");
    if (chdir("/") < 0)
      child_die("chdir /");
  }
}

static int child_helper(void *arg) {
  const child_cfg_t *cfg = (const child_cfg_t *)arg;

  setup_user_ns(cfg);
  setup_mounts(cfg);

  if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0)
    _exit(127);
  raise(SIGSTOP);

  if (cfg->mode == MODE_HYBRID) {
    if (cfg->profile_file)
      seccomp_profile_start(cfg->profile_file);
    else
      seccompp_filter_start();
  }

  execv(cfg->target, cfg->target_argv);
  fprintf(stderr, "sandbox(child): cannot exec %s: %s\n", cfg->target,
          strerror(errno));
  _exit(127);
}

static void usage(const char *prog) {
  fprintf(
      stderr,
      "usage: %s [options] [--] TARGET [ARGS...]\n"
      "  --rootfs DIR           pivot_root into DIR (target path is inside "
      "it)\n"
      "  --log FILE             write the JSON log to FILE\n"
      "  --audit                log every verdict but always allow\n"
      "  --mode=hybrid|trace    hybrid (default) or trace-all (strace clone)\n"
      "  --record FILE          trace-all, then write the syscall names used\n"
      "  --profile FILE         default-kill filter allowing only FILE's "
      "names\n"
      "  --unsafe-path-policy   DEBUG: decide on the decoded path (racy!)\n"
      "  --protected-path P     path used by --unsafe-path-policy\n"
      "  --race-delay-us N      DEBUG: sleep N us after a file decision\n"
      "  -v, --verbose          print every wait status and event\n",
      prog);
}

static int ptrace_main(int argc, char *argv[]) {
  child_cfg_t cfg = {.uid = getuid(),
                     .gid = getgid(),
                     .mode = MODE_HYBRID,
                     .protected_path = "/protected/secret.txt"};
  char *rootfs_real = NULL;

  enum { OPT_AUDIT = 256, OPT_UNSAFE, OPT_PROTECTED, OPT_DELAY };
  static const struct option opts[] = {
      {"rootfs", required_argument, 0, 'r'},
      {"log", required_argument, 0, 'l'},
      {"audit", no_argument, 0, OPT_AUDIT},
      {"mode", required_argument, 0, 'm'},
      {"record", required_argument, 0, 'R'},
      {"profile", required_argument, 0, 'P'},
      {"unsafe-path-policy", no_argument, 0, OPT_UNSAFE},
      {"protected-path", required_argument, 0, OPT_PROTECTED},
      {"race-delay-us", required_argument, 0, OPT_DELAY},
      {"verbose", no_argument, 0, 'v'},
      {0, 0, 0, 0}};

  int c;

  while ((c = getopt_long(argc, argv, "+v", opts, NULL)) != -1) {
    switch (c) {
    case 'r':
      rootfs_real = realpath(optarg, NULL);
      if (!rootfs_real) {
        fprintf(stderr, "rootfs %s: %s\n", optarg, strerror(errno));
        return 2;
      }
      cfg.rootfs = rootfs_real;
      break;
    case 'l':
      cfg.log_file = optarg;
      break;
    case 'm':
      if (!strcmp(optarg, "trace"))
        cfg.mode = MODE_TRACE;
      else if (!strcmp(optarg, "hybrid"))
        cfg.mode = MODE_HYBRID;
      else {
        usage(argv[0]);
        return 2;
      }
      break;
    case 'R':
      cfg.record_file = optarg;
      cfg.mode = MODE_TRACE;
      break;
    case 'P':
      cfg.profile_file = optarg;
      break;
    case OPT_AUDIT:
      cfg.audit = 1;
      break;
    case OPT_UNSAFE:
      cfg.unsafe_path_policy = 1;
      break;
    case OPT_PROTECTED:
      cfg.protected_path = optarg;
      break;
    case OPT_DELAY:
      cfg.race_delay = atol(optarg);
      break;
    case 'v':
      cfg.verbose = 1;
      break;
    default:
      usage(argv[0]);
      return 2;
    }
  }
  if (optind >= argc) {
    usage(argv[0]);
    return 2;
  }
  cfg.target = argv[optind];
  cfg.target_argv = &argv[optind];

  logger_init(cfg.log_file, cfg.verbose);
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
    perror("Clone failed (try sudo, or check unprivileged user namespaces)");
    free(stack);
    destroy_cgroup();
    exit(EXIT_FAILURE);
  }

  int status = 0;
  pid_t wait_pid = waitpid(process_pid, &status, 0);
  if (wait_pid < 0 || !WIFSTOPPED(status)) {
    if (wait_pid >= 0 && WIFEXITED(status))
      fprintf(stderr, "Child setup failed (exit code %d), see message above\n",
              WEXITSTATUS(status));
    else
      fprintf(stderr, "Child failed to stop initially\n");
    destroy_cgroup();
    exit(EXIT_FAILURE);
  }

  attach_cgroup(process_pid);

  PTRACE_CHECK(PTRACE_SETOPTIONS, process_pid, 0,
               (void *)(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD |
                        PTRACE_O_TRACESECCOMP | PTRACE_O_TRACEEXEC |
                        PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
                        PTRACE_O_TRACEVFORK));

  policy_state_t state = {0};
  int exit_code = run_multi(process_pid, &cfg, &state);

  long oom = cgroup_oom_kills();
  logger_exit_summary(exit_code, state.violation_count, oom);
  if (cfg.record_file)
    record_write(cfg.record_file);
  destroy_cgroup();
  free(stack);
  free(rootfs_real);
  return exit_code;
}

int main(int argc, char *argv[]) { return ptrace_main(argc, argv); }
