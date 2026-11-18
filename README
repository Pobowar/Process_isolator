# A Lightweight Process Isolator for Untrusted Binaries

**Author:** Bhavesh Kumar (20251503015)  
**Course:** AI201 — Indian Institute of Information Technology Vadodara  

---

## How It Works

Running an untrusted binary on Linux normally gives it all the privileges of the current user , it can open any file, make network connections, spawn unlimited processes, and call privileged syscalls. This project aims to solve that issue by building a sandbox that puts the untrusted binary inside a isolated envirement with its own file system , mount points, memory limit, process restriction, PID, network and namespace. After which the system calls by the binary is checked by Seccomp BPF and if action is needed send to the supervisor block (Ptrace) in user space. 


### Building Blocks Used   

**Namespaces + root filesystem**  
The target is launched with `clone()` using `CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET`. It becomes PID 1 in its own PID namespace (so it can't see host processes), has its own network namespace (no outside network), and sees minimal root filesystem instead of the host's root system. Files that don't exist in the sandbox root cannot be opened inside the sandbox. 

**Seccomp BPF + ptrace supervisor**  
Every syscall the binary makes is first sended to BPF. "Safe" syscalls (read, write, getpid,etc) pass straight through with zero extra overhead to the kernal. Only a small watch list of sensitive syscalls (`open`, `socket`, `execve`, `mount`, `ptrace`) return `SECCOMP_RET_TRACE`, which stops the target and wakes the supervisor. The supervisor reads the CPU registers, applies the policy, writes a JSON log line, and either resumes the target or denies/kills it. This hybrid approach is about 2× slower than a plain run, versus 12× slower for a pure ptrace trace all syscall approach.

**cgroup v2 resource limits**  
Before the target runs anything, the supervisor places it in a cgroup with hard limits: 512 MiB memory, 1 CPU, 64 processes. A memory hog or fork bomb hits these limits and is killed by the kernel OOM killer. The `oom_kill` counter from `memory.events` is printed in the exit summary.

### Policy decisions

The policy is a pure function `evaluate(call, state)` → `{allow, deny, kill}`. It decides only on **scalar arguments** (flags, domain numbers) that are safely copied into registers — never on pointer contents like path strings. This avoids the TOCTOU race (see Security section). Key rules:

| Syscall | Rule | Result |
|---|---|---|
| `execve` / `execveat` | First is the target; later ones are logged | allow |
| `open`, `openat`, `creat` | Write flags (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`) | deny (EPERM) |
| `openat2` | Flags are behind a pointer — not scalar | deny (ENOSYS) |
| `socket` | Domain ≠ `AF_UNIX` | deny (EPERM) |
| `connect`, `bind` | No INET socket can exist anyway | log, allow |
| `mount`, `ptrace`, `unshare`, `setns`, `pivot_root`, `chroot`, `bpf`, `init_module` | Privileged calls | deny; kill on 3rd violation |

---

## Requirements

```bash
# Debian / Ubuntu
sudo apt install build-essential gcc libseccomp-dev strace jq busybox-static

# Check environment
uname -m                            # must be x86_64
cat /proc/sys/kernel/yama/ptrace_scope   # 0–2 is fine; 3 blocks ptrace
stat -fc %T /sys/fs/cgroup          # "cgroup2fs" = cgroup v2 (needed for resource limits)
```

---

## Build

```bash
# Build the sandbox and all test programs
make

# Or manually
gcc -Wall -Wextra -g ptrace.c BPF.c cgroup_v2.c log.c policy.c -lseccomp -o sandbox
```

---

## Basic Usage

```bash
# Run any binary under the sandbox (hybrid mode, default)
./sandbox /bin/ls /tmp

# Trace-all mode — same syscall list as strace (use as oracle / baseline)
./sandbox --mode=trace /bin/true

# Write a JSON log of every decision
./sandbox --log run.log /bin/ls /tmp
cat run.log | jq .

# Use a minimal root filesystem (target path must exist inside it)
./sandbox --rootfs ./rootfs /bin/hello

# Audit mode — log everything but never deny (safe for tuning)
./sandbox --audit ./tests/writer

# Record the syscalls a program uses, then enforce exactly that set
./sandbox --record true.prof /bin/true
./sandbox --profile true.prof /bin/ls /tmp   # ls is killed (SIGSYS, exit 159)

# Verbose mode — print every ptrace stop
./sandbox -v /bin/true

# Propagate exit codes
./sandbox /bin/false; echo $?    # prints 1
```

---

## Running the Test Targets

Each test program is in `tests/`. Build them individually or add them to the Makefile.

```bash
cd tests
gcc -Wall -g hello.c      -o hello
gcc -Wall -g writer.c     -o writer
gcc -Wall -g net.c        -o net
gcc -Wall -g exec_chain.c -o exec_chain
gcc -Wall -g threads.c    -pthread -o threads
gcc -Wall -g priv.c       -o priv
gcc -Wall -g hog.c        -o hog

cd attacks
gcc -Wall -g a1_net.c     -o a1_net
gcc -Wall -g a2_revshell.c -o a2_revshell
gcc -Wall -g a3_write.c   -o a3_write
gcc -Wall -g a4_priv.c    -o a4_priv
gcc -Wall -g a5_hog.c     -o a5_hog
gcc -Wall -g a6_toctou.c  -pthread -o a6_toctou
```

### Functional tests

```bash
# Clean run — only loader events, exit 0
./sandbox ./tests/hello

# Write-open denied (EPERM)
./sandbox ./tests/writer

# AF_INET denied, AF_UNIX allowed
./sandbox ./tests/net

# Both execs logged and allowed
./sandbox ./tests/exec_chain

# 4 threads × 5 opens = 20 FILE events across 4 tids
./sandbox ./tests/threads

# mount/unshare/ptrace: denied twice, killed on 3rd
./sandbox ./tests/priv

# Memory hog: killed by cgroup (needs root + cgroup v2)
sudo ./sandbox ./tests/hog
```

### Attack replication (Table II from the report)

```bash
# A1: socket(AF_INET) — denied by policy + network namespace
./sandbox ./tests/attacks/a1_net

# A2: reverse-shell chain — stops at first socket call
./sandbox ./tests/attacks/a2_revshell

# A3: open /etc/passwd for writing — denied by flags rule (scalar)
./sandbox ./tests/attacks/a3_write

# A4: mount/unshare/ptrace — denied, killed on 3rd
./sandbox ./tests/attacks/a4_priv

# A5: memory hog + fork bomb — stopped by cgroup (needs root)
sudo ./sandbox ./tests/attacks/a5_hog

# A6: TOCTOU race demo
#   Weak policy (bypass possible with race delay):
sudo ./sandbox --unsafe-path-policy \
               --protected-path /protected/secret.txt \
               --race-delay-us 2000 \
               ./tests/attacks/a6_toctou /protected/secret.txt
#   Intended design (protected file outside rootfs → ENOENT, race irrelevant):
sudo ./sandbox --rootfs ./rootfs \
               --unsafe-path-policy \
               ./tests/attacks/a6_toctou /protected/secret.txt
```

---

## Security Notes

### TOCTOU stance
The supervisor reads a path string from the target's memory at the seccomp stop. But another thread of the target could change that buffer before the kernel reads it again when the syscall resumes. This is the **time-of-check-to-time-of-use (TOCTOU) race**. Our policy avoids this by deciding only on scalar arguments (flags, socket domain) that are safely in registers — never on path strings. Decoded paths appear in the log as advisory context only. The race-free alternative (a BPF-LSM hook or Landlock) is left as future work.

### Limitations
- x86-64 only (register names are architecture-specific)
- Needs root or a delegated cgroup subtree for resource limits
- `no_new_privs` blocks setuid programs (`sudo`, `ping`) inside the sandbox
- `execve` from a non-leader thread of a multi-threaded process is not supported
- Kernel vulnerabilities, side channels, and a malicious supervisor are out of scope

---

## Building the Root Filesystem

```bash
mkdir -p rootfs/bin rootfs/proc rootfs/tmp rootfs/etc
cp /bin/busybox rootfs/bin/
for cmd in sh ls cat echo true false id find; do
    ln -sf busybox rootfs/bin/$cmd
done
echo "sandbox-host" > rootfs/etc/hostname
```
