#include "define.h"

static int log_fd = -1;

void logger_init(const char *filename) {
  if (filename) {
    log_fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  }
}

void logger_log_event(pid_t pid, const char *sys_name, long tag, int denied) {
  char buf[512];
  int len = snprintf(
      buf, sizeof(buf),
      "{\"pid\": %d, \"syscall\": \"%s\", \"tag\": %ld, \"denied\": %s}\n", pid,
      sys_name ? sys_name : "UNKNOWN", tag, denied ? "true" : "false");

  if (log_fd >= 0) {
    write(log_fd, buf, len);
  }
  write(STDERR_FILENO, buf, len); // Supervisor output go to stderr
}

void logger_exit_summary(int status, int total_violations) {
  char buf[256];
  int len = snprintf(buf, sizeof(buf),
                     "{\"exit_status\": %d, \"total_violations\": %d}\n",
                     status, total_violations);
  if (log_fd >= 0) {
    write(log_fd, buf, len);
    close(log_fd);
  }
  write(STDERR_FILENO, buf, len);
}
