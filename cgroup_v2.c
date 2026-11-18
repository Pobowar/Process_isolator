#include <sys/vfs.h>

#include "define.h"

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif

static int cgroup_is_active = 0;

static int write_string_to_file(const char *file_path, const char *content) {
  int fd = open(file_path, O_WRONLY | O_CLOEXEC);
  if (fd < 0)
    return -1;
  ssize_t bytes_written = write(fd, content, strlen(content));
  int saved_errno = errno;
  close(fd);
  errno = saved_errno;
  return bytes_written < 0 ? -1 : 0;
}

static void set_cgroup_parameter(const char *param_file,
                                 const char *limit_value) {
  char full_path[256];
  snprintf(full_path, sizeof full_path, "%s/%s", CGROUP_PATH, param_file);
  if (write_string_to_file(full_path, limit_value) < 0)
    fprintf(stderr, "[cgroup] cannot set %s=%s: %s\n", param_file, limit_value,
            strerror(errno));
}

int setup_cgroup(void) {
  struct statfs filesystem_stats;
  if (statfs("/sys/fs/cgroup", &filesystem_stats) < 0 ||
      filesystem_stats.f_type != CGROUP2_SUPER_MAGIC) {
    fprintf(stderr,
            "[cgroup] /sys/fs/cgroup is not cgroup v2 (check: stat -fc %%T "
            "/sys/fs/cgroup) - continuing WITHOUT resource limits\n");
    return -1;
  }
  if (mkdir(CGROUP_PATH, 0755) < 0 && errno != EEXIST) {
    fprintf(stderr,
            "[cgroup] cannot create %s: %s (is this cgroup v2, running as "
            "root?) - continuing WITHOUT resource limits\n",
            CGROUP_PATH, strerror(errno));
    return -1;
  }
  cgroup_is_active = 1;

  const char *controllers[] = {"+pids", "+memory", "+cpu"};
  for (size_t i = 0; i < ARRAY_SIZE(controllers); i++)
    if (write_string_to_file("/sys/fs/cgroup/cgroup.subtree_control",
                             controllers[i]) < 0 &&
        errno != EBUSY)
      fprintf(stderr, "[cgroup] enabling %s failed: %s\n", controllers[i],
              strerror(errno));

  set_cgroup_parameter("memory.max", CG_MEMORY_MAX);
  set_cgroup_parameter("cpu.max", CG_CPU_MAX);
  set_cgroup_parameter("pids.max", CG_PIDS_MAX);
  return 0;
}

void attach_cgroup(pid_t pid) {
  if (!cgroup_is_active)
    return;
  char path[256], pid_str[32];
  snprintf(path, sizeof path, "%s/cgroup.procs", CGROUP_PATH);
  snprintf(pid_str, sizeof pid_str, "%d", pid);
  if (write_string_to_file(path, pid_str) < 0)
    fprintf(stderr, "[cgroup] cannot attach pid %d: %s\n", pid,
            strerror(errno));
}

long cgroup_oom_kills(void) {
  if (!cgroup_is_active)
    return -1;
  char path[256];
  snprintf(path, sizeof path, "%s/memory.events", CGROUP_PATH);
  FILE *file_ptr = fopen(path, "r");
  if (!file_ptr)
    return -1;
  char event_key[64];
  long event_val, oom_count = -1;
  while (fscanf(file_ptr, "%63s %ld", event_key, &event_val) == 2)
    if (strcmp(event_key, "oom_kill") == 0)
      oom_count = event_val;
  fclose(file_ptr);
  return oom_count;
}

void destroy_cgroup(void) {
  if (!cgroup_is_active)
    return;
  for (int i = 0; i < 20; i++) {
    if (rmdir(CGROUP_PATH) == 0 || errno == ENOENT)
      return;
    usleep(10000);
  }
  fprintf(stderr, "[cgroup] could not remove %s: %s\n", CGROUP_PATH,
          strerror(errno));
}
