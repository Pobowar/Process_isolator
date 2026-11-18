#ifndef _GNU_SOURCE
// need for clone , do not touch
#define _GNU_SOURCE
#include <sched.h>
#endif

#ifndef ptrace_header

#define ptrace_header
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <asm-generic/errno-base.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

// micro
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
#endif

// seccompt filter header start
#ifndef seccompt_filter

#define seccompt_filter

#include <libseccomp/seccomp.h>

#define TAG_EXEC 1
#define TAG_OPEN 2
#define TAG_NET 3
#define TAG_PRIV 4

typedef struct {
  const char *name;
  int tag;
} watch_rule_t;

void seccompp_filter_start();

#endif

// isolation and cgroup v2
#ifndef isolator
#define isolator
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>

typedef struct {
  uid_t uid;
  gid_t gid;
  const char *rootfs;
  const char *target;
  const char *log_file;
  int verbose;
} child_cfg_t;

#define CGROUP_PATH "/sys/fs/cgroup/sandbox_cg"
#define AF_UNIX 1
#endif
