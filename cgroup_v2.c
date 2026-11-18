#include "define.h"

void setup_cgroup(void) {
  // Create cgroup v2 directory
  mkdir(CGROUP_PATH, 0755);

  int fd = open("/sys/fs/cgroup/cgroup.subtree_control", O_WRONLY);
  if (fd >= 0) {
    write(fd, "+pids +memory +cpu", 18);
    close(fd);
  }
}

void attach_cgroup(pid_t pid) {
  char procs_path[512];
  snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", CGROUP_PATH);

  int fd = open(procs_path, O_WRONLY);
  if (fd >= 0) {
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", pid);
    write(fd, pid_str, strlen(pid_str));
    close(fd);
  }
}

void destroy_cgroup(void) { rmdir(CGROUP_PATH); }
