all:
	gcc ptrace.c BPF.c cgroup_v2.c log.c policy.c -lseccomp -o sandbox
	gcc test.c -o test
