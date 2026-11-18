#include <libseccomp/seccomp.h>

#include <stdio.h>
#include <stdlib.h>

#include "define.h"

void seccompp_filter_start() {
  // will start before anything and decide the what syscall has what priority .
  // main context creation and allowing every other syscall and filtering
  // specific
  scmp_filter_ctx context = seccomp_init(SCMP_ACT_ALLOW);
  if (context == NULL) {
    fprintf(stderr, "seccompt context creation failed");
    exit(EXIT_FAILURE);
  }
  const watch_rule_t watch_list[] = {
      {"execve", TAG_EXEC},     {"execveat", TAG_EXEC}, {"open", TAG_OPEN},
      {"openat", TAG_OPEN},     {"openat2", TAG_OPEN},  {"creat", TAG_OPEN},
      {"socket", TAG_NET},      {"connect", TAG_NET},   {"mount", TAG_PRIV},
      {"ptrace", TAG_PRIV},     {"unshare", TAG_PRIV},  {"setns", TAG_PRIV},
      {"pivot_root", TAG_PRIV}, {"chroot", TAG_PRIV}};
  int size_watch_list = ARRAY_SIZE(watch_list);

  for (int i = 0; i < size_watch_list; i++) {
    int syscall_id = seccomp_syscall_resolve_name(watch_list[i].name);
    if (syscall_id < 0) {
      continue;
    }
    // marking what actions need to perform for the syscalls
    if (seccomp_rule_add(context, SCMP_ACT_TRACE(watch_list[i].tag), syscall_id,
                         0) < 0) {
      fprintf(stderr, "seccomp rule add failed for %s", watch_list[i].name);
      seccomp_release(context);
      exit(EXIT_FAILURE);
    }
  }
  if (seccomp_load(context) < 0) {
    fprintf(stderr, "seccompt context was not loaded properly ");
    seccomp_release(context);
    exit(EXIT_FAILURE);
  }
  seccomp_release(context); // this context was only for user space
}
