#ifndef header_file
#define header_file

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__x86_64__)
#error
#endif

#include <sched.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

#if defined(__has_include)
#if __has_include(<seccomp.h>)
#include <seccomp.h>
#else
#include <libseccomp/seccomp.h>
#endif
#else
#include <seccomp.h>
#endif

// macros
#define PTRACE_CHECK(...)                                                      \
  do {                                                                         \
    errno = 0;                                                                 \
    if (ptrace(__VA_ARGS__) == -1) {                                           \
      fprintf(stderr, "%s:%d: ptrace(%s) failed: %s\n", __FILE__, __LINE__,    \
              #__VA_ARGS__, strerror(errno));                                  \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define STACK_SIZE (1024 * 1024)
#define MAX_TIDS 1024

// seccomp filter

#define TAG_EXEC 1
#define TAG_OPEN 2
#define TAG_NET 3
#define TAG_PRIV 4

static inline const char *tag_name(long tag) {
  switch (tag) {
  case TAG_EXEC:
    return "EXEC";
  case TAG_OPEN:
    return "FILE";
  case TAG_NET:
    return "NET";
  case TAG_PRIV:
    return "PRIV";
  default:
    return "OTHER";
  }
}

typedef struct {
  const char *name;
  int tag;
} watch_rule_t;

#define CGROUP_PATH "/sys/fs/cgroup/sandbox_cg"
#define CG_MEMORY_MAX "536870912"
#define CG_CPU_MAX "100000 100000"
#define CG_PIDS_MAX "64"

typedef enum {
  MODE_HYBRID, // seccomp RET_TRACE + PTRACE_CONT (default)
  MODE_TRACE   // trace-all baseline: PTRACE_SYSCALL
} run_mode_t;

typedef struct {
  uid_t uid; // outer uid/gid, mapped to 0 inside the user namespace
  gid_t gid;
  const char *rootfs;       // NULL = keep the host filesystem
  const char *target;       // path of the program (argv[0])
  char *const *target_argv; // NULL terminated, points into main's argv
  const char *log_file;
  const char *record_file;    // --record: write the syscall names used
  const char *profile_file;   // --profile: default-kill filter from a file
  const char *protected_path; // used only by --unsafe-path-policy
  int verbose;
  int audit;              // log every verdict but always allow
  int unsafe_path_policy; // DEBUG: decide on the decoded path
  long race_delay;
  run_mode_t mode;
} child_cfg_t;

typedef struct {
  pid_t tids[MAX_TIDS];
  int count;
} tid_set_t;

typedef struct {
  int violation_count;
  int priv_count;
  int exec_count;
} policy_state_t;

typedef struct {
  const char *name;
  long tag;
  unsigned long args[6];
  const char *path;
} call_t;

typedef enum { ACT_ALLOW = 0, ACT_DENY = 1, ACT_KILL = 2 } action_t;

typedef struct {
  action_t action;
  int err;
  const char *severity;
  const char *reason;
} verdict_t;

void seccompp_filter_start(void);
void seccomp_profile_start(const char *profile);

// cgroup_v2
int setup_cgroup(void);
void attach_cgroup(pid_t pid);
long cgroup_oom_kills(void);
void destroy_cgroup(void);

// policy
verdict_t evaluate(const call_t *c, policy_state_t *state,
                   int unsafe_path_policy, const char *protected_path);

// log
void logger_init(const char *filename, int verbose);
void logger_log_event(pid_t tid, const call_t *c, const verdict_t *v,
                      int enforced);
void logger_exit_summary(int status, int total_violations, long oom_kills);

#endif
