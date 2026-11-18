#include "define.h"

static int log_file_descriptor = -1;
static int should_log_to_stderr = 1;

#define MAX_SYSCALL_TRACKED 128
static struct {
  char syscall_name[32];
  long invocation_count;
} syscall_stats[MAX_SYSCALL_TRACKED];
static int tracked_syscall_count;
static long verdict_tally[3]; // allow, deny, kill

void logger_init(const char *log_filepath, int verbose_mode) {
  if (log_filepath) {
    // O_CLOEXEC ->  the untrusted target must NOT inherit the log descriptor
    log_file_descriptor =
        open(log_filepath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (log_file_descriptor < 0)
      fprintf(stderr, "cannot open log %s: %s\n", log_filepath,
              strerror(errno));
  }
  // without a log file the events would vanish, so then use stderr
  should_log_to_stderr = verbose_mode || log_file_descriptor < 0;
}

static size_t escape_json_string(char *destination, size_t capacity,
                                 const char *source) {
  size_t written_len = 0;
  for (const unsigned char *p = (const unsigned char *)source; *p; p++) {
    if (written_len + 8 > capacity)
      break;
    switch (*p) {
    case '"':
      destination[written_len++] = '\\';
      destination[written_len++] = '"';
      break;
    case '\\':
      destination[written_len++] = '\\';
      destination[written_len++] = '\\';
      break;
    case '\n':
      destination[written_len++] = '\\';
      destination[written_len++] = 'n';
      break;
    case '\r':
      destination[written_len++] = '\\';
      destination[written_len++] = 'r';
      break;
    case '\t':
      destination[written_len++] = '\\';
      destination[written_len++] = 't';
      break;
    default:
      if (*p < 0x20 || *p >= 0x7f)
        written_len += (size_t)snprintf(destination + written_len,
                                        capacity - written_len, "\\u%04x", *p);
      else
        destination[written_len++] = (char)*p;
    }
  }
  destination[written_len] = 0;
  return written_len;
}

static const char *get_errno_name(int error_code) {
  switch (error_code) {
  case 0:
    return NULL;
  case EPERM:
    return "EPERM";
  case ENOSYS:
    return "ENOSYS";
  default:
    return "EOTHER";
  }
}

static void write_log_output(const char *buffer, size_t length) {
  if (log_file_descriptor >= 0)
    (void)!write(log_file_descriptor, buffer, length);
  if (should_log_to_stderr)
    (void)!write(STDERR_FILENO, buffer, length);
}

static void register_event_count(const char *syscall_name, action_t action) {
  verdict_tally[action]++;
  for (int i = 0; i < tracked_syscall_count; i++)
    if (strcmp(syscall_stats[i].syscall_name, syscall_name) == 0) {
      syscall_stats[i].invocation_count++;
      return;
    }
  if (tracked_syscall_count < MAX_SYSCALL_TRACKED) {
    snprintf(syscall_stats[tracked_syscall_count].syscall_name,
             sizeof syscall_stats[tracked_syscall_count].syscall_name, "%s",
             syscall_name);
    syscall_stats[tracked_syscall_count++].invocation_count = 1;
  }
}

void logger_log_event(pid_t thread_id, const call_t *call_info,
                      const verdict_t *verdict, int is_enforced) {
  static char log_buffer[40000];
  static char escaped_buffer[30000];
  struct timespec timestamp;
  clock_gettime(CLOCK_REALTIME, &timestamp);

  const char *syscall_name = call_info->name ? call_info->name : "UNKNOWN";
  size_t buffer_index = 0;
#define APPEND(...)                                                            \
  do {                                                                         \
    int chars_written =                                                        \
        snprintf(log_buffer + buffer_index, sizeof log_buffer - buffer_index,  \
                 __VA_ARGS__);                                                 \
    if (chars_written > 0)                                                     \
      buffer_index +=                                                          \
          ((size_t)chars_written < sizeof log_buffer - buffer_index)           \
              ? (size_t)chars_written                                          \
              : sizeof log_buffer - buffer_index - 1;                          \
  } while (0)

  APPEND("{\"ts\":%ld.%06ld,\"tid\":%d,\"syscall\":\"%s\",\"tag\":\"%s\","
         "\"args\":[",
         (long)timestamp.tv_sec, timestamp.tv_nsec / 1000, thread_id,
         syscall_name, tag_name(call_info->tag));
  for (int i = 0; i < 6; i++)
    APPEND("%s\"0x%lx\"", i ? "," : "", call_info->args[i]);
  APPEND("],");

  if (call_info->path) { // advisory log context, never used for a hard decision
    escape_json_string(escaped_buffer, sizeof escaped_buffer, call_info->path);
    APPEND("\"path\":\"%s\",\"path_status\":\"advisory\",", escaped_buffer);
  }

  const char *verdict_str = verdict->action == ACT_ALLOW  ? "allow"
                            : verdict->action == ACT_DENY ? "deny"
                                                          : "kill";
  const char *errno_str = get_errno_name(verdict->err);
  APPEND("\"verdict\":\"%s\",\"enforced\":%s,", verdict_str,
         is_enforced ? "true" : "false");
  if (errno_str && verdict->action != ACT_ALLOW)
    APPEND("\"errno\":\"%s\",", errno_str);
  else
    APPEND("\"errno\":null,");
  escape_json_string(escaped_buffer, sizeof escaped_buffer, verdict->reason);
  APPEND("\"severity\":\"%s\",\"reason\":\"%s\"}\n", verdict->severity,
         escaped_buffer);
#undef APPEND

  register_event_count(syscall_name, verdict->action);
  write_log_output(log_buffer, buffer_index);
}

void logger_exit_summary(int exit_status, int total_violations,
                         long oom_kills_count) {
  static char summary_buffer[8192];
  size_t buffer_index = 0;
#define APPEND(...)                                                            \
  do {                                                                         \
    int chars_written =                                                        \
        snprintf(summary_buffer + buffer_index,                                \
                 sizeof summary_buffer - buffer_index, __VA_ARGS__);           \
    if (chars_written > 0)                                                     \
      buffer_index +=                                                          \
          ((size_t)chars_written < sizeof summary_buffer - buffer_index)       \
              ? (size_t)chars_written                                          \
              : sizeof summary_buffer - buffer_index - 1;                      \
  } while (0)

  APPEND("{\"exit_status\":%d,\"total_violations\":%d", exit_status,
         total_violations);
  if (oom_kills_count >= 0)
    APPEND(",\"oom_kill\":%ld", oom_kills_count);
  APPEND(",\"by_verdict\":{\"allow\":%ld,\"deny\":%ld,\"kill\":%ld}",
         verdict_tally[ACT_ALLOW], verdict_tally[ACT_DENY],
         verdict_tally[ACT_KILL]);
  APPEND(",\"by_syscall\":{");
  for (int i = 0; i < tracked_syscall_count; i++)
    APPEND("%s\"%s\":%ld", i ? "," : "", syscall_stats[i].syscall_name,
           syscall_stats[i].invocation_count);
  APPEND("}}\n");
#undef APPEND

  if (log_file_descriptor >= 0) {
    (void)!write(log_file_descriptor, summary_buffer, buffer_index);
    close(log_file_descriptor);
    log_file_descriptor = -1;
  }
  (void)!write(STDERR_FILENO, summary_buffer, buffer_index);
}
