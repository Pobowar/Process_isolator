#include "define.h"

static verdict_t create_verdict(action_t action, int error_code,
                                const char *severity, const char *reason) {
  verdict_t verdict = {action, error_code, severity, reason};
  return verdict;
}

static verdict_t decide_policy(const call_t *call_info, policy_state_t *state,
                               int unsafe_path_policy,
                               const char *protected_path) {
  const char *syscall_name = call_info->name ? call_info->name : "";

  switch (call_info->tag) {

  // privileged calls: deny (kill on the 3rd)
  case TAG_PRIV:
    state->priv_count++;
    if (state->priv_count >= 3)
      return create_verdict(ACT_KILL, EPERM, "dangerous",
                            "privileged syscall, 3rd violation");
    return create_verdict(ACT_DENY, EPERM, "dangerous", "privileged syscall");

  // exec: the first one is the target itself, later ones are logged
  case TAG_EXEC:
    state->exec_count++;
    if (state->exec_count == 1)
      return create_verdict(ACT_ALLOW, 0, "benign",
                            "first execve is the target");
    return create_verdict(ACT_ALLOW, 0, "suspicious", "additional execve");

  case TAG_OPEN: {
    // openat2: flags live in a struct behind a pointer, so they are not a
    //  scalar. Fail with ENOSYS so callers fall back to openat.
    if (strcmp(syscall_name, "openat2") == 0)
      return create_verdict(ACT_DENY, ENOSYS, "suspicious",
                            "openat2 flags are behind a pointer (not scalar)");

    int open_flags = 0;
    if (strcmp(syscall_name, "open") == 0)
      open_flags = (int)call_info->args[1]; // open(path, flags, mode)
    else if (strcmp(syscall_name, "openat") == 0)
      open_flags = (int)call_info->args[2]; // openat(dirfd, path, flags, mode)
    else if (strcmp(syscall_name, "creat") == 0)
      open_flags = O_WRONLY | O_CREAT | O_TRUNC; // creat always writes

    if ((open_flags & O_ACCMODE) != O_RDONLY ||
        (open_flags & (O_CREAT | O_TRUNC)) ||
        (open_flags & O_TMPFILE) == O_TMPFILE)
      return create_verdict(ACT_DENY, EPERM, "suspicious", "write-open");

    if (unsafe_path_policy && call_info->path && protected_path &&
        strcmp(call_info->path, protected_path) == 0)
      return create_verdict(ACT_DENY, EPERM, "suspicious",
                            "unsafe-path-policy: decoded path is protected");

    return create_verdict(ACT_ALLOW, 0, "benign", "read-only open");
  }

  case TAG_NET:
    if (strcmp(syscall_name, "socket") == 0) {
      int socket_domain = (int)call_info->args[0];
      if (socket_domain != AF_UNIX)
        return create_verdict(ACT_DENY, EPERM, "dangerous",
                              "socket domain is not AF_UNIX");
      return create_verdict(ACT_ALLOW, 0, "benign", "AF_UNIX socket");
    }
    return create_verdict(ACT_ALLOW, 0, "suspicious", "connect/bind logged");

  default:
    return create_verdict(ACT_ALLOW, 0, "benign", "not restricted");
  }
}

verdict_t evaluate(const call_t *call_info, policy_state_t *state,
                   int unsafe_path_policy, const char *protected_path) {
  verdict_t verdict =
      decide_policy(call_info, state, unsafe_path_policy, protected_path);
  if (verdict.action != ACT_ALLOW)
    state->violation_count++;
  return verdict;
}
