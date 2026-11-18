/*
 * hello.c - clean program test target
 *
 * Expected behaviour under sandbox:
 *   - Only loader openat events (libc, ld.so.cache) in the log
 *   - Exits with code 0
 *   - No denied syscalls
 */

#include <stdio.h>

int main(void) {
    printf("hello from sandbox target\n");
    return 0;
}
