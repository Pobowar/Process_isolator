#include "define.h"

static const watch_rule_t watch_list[] = {
    {"execve", TAG_EXEC}, {"execveat", TAG_EXEC},   {"open", TAG_OPEN},
    {"openat", TAG_OPEN}, {"openat2", TAG_OPEN},    {"creat", TAG_OPEN},
    {"socket", TAG_NET},  {"connect", TAG_NET},     {"bind", TAG_NET},
    {"mount", TAG_PRIV},  {"ptrace", TAG_PRIV},     {"unshare", TAG_PRIV},
    {"setns", TAG_PRIV},  {"pivot_root", TAG_PRIV}, {"chroot", TAG_PRIV},
    {"bpf", TAG_PRIV},    {"init_module", TAG_PRIV}};

static int watch_tag(const char *name) {
  for (size_t i = 0; i < ARRAY_SIZE(watch_list); i++) {
    if (strcmp(watch_list[i].name, name) == 0)
      return watch_list[i].tag;
  }
  return 0;
}

void seccompp_filter_start(void) {
  scmp_filter_ctx context = seccomp_init(SCMP_ACT_ALLOW);
  if (context == NULL) {
    fprintf(stderr, "seccomp context creation failed\n");
    exit(EXIT_FAILURE);
  }

  for (size_t i = 0; i < ARRAY_SIZE(watch_list); i++) {
    int syscall_id = seccomp_syscall_resolve_name(watch_list[i].name);
    if (syscall_id < 0)
      continue; // not available in architecture

    if (seccomp_rule_add(context, SCMP_ACT_TRACE(watch_list[i].tag), syscall_id,
                         0) < 0) {
      fprintf(stderr, "seccomp rule add failed for %s\n", watch_list[i].name);
      seccomp_release(context);
      exit(EXIT_FAILURE);
    }
  }

  if (seccomp_load(context) < 0) {
    fprintf(stderr, "seccomp context was not loaded properly\n");
    seccomp_release(context);
    exit(EXIT_FAILURE);
  }

  seccomp_release(context);
}

static void profile_allow(scmp_filter_ctx ctx, const char *name) {
  int nr = seccomp_syscall_resolve_name(name);
  if (nr < 0)
    return;

  int tag = watch_tag(name);
  uint32_t action = tag ? SCMP_ACT_TRACE(tag) : SCMP_ACT_ALLOW;
  int rc = seccomp_rule_add(ctx, action, nr, 0);
  if (rc < 0 && rc != -EEXIST) {
    fprintf(stderr, "profile: rule add failed for %s\n", name);
    exit(EXIT_FAILURE);
  }
}

void seccomp_profile_start(const char *profile) {
  FILE *f = fopen(profile, "r");
  if (!f) {
    fprintf(stderr, "cannot open profile %s: %s\n", profile, strerror(errno));
    exit(EXIT_FAILURE);
  }

  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
  if (!ctx) {
    fprintf(stderr, "seccomp context creation failed\n");
    exit(EXIT_FAILURE);
  }

  // these two are always needed: execve starts the target, exit_group ends it
  profile_allow(ctx, "execve");
  profile_allow(ctx, "exit_group");

  char line[128];
  while (fgets(line, sizeof line, f)) {
    line[strcspn(line, "\r\n")] = 0;
    if (line[0] && line[0] != '#')
      profile_allow(ctx, line);
  }
  fclose(f);

  if (seccomp_load(ctx) < 0) {
    fprintf(stderr, "profile filter was not loaded\n");
    exit(EXIT_FAILURE);
  }
}
