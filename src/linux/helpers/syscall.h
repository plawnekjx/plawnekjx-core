#ifndef __PLAWNEKJX_SYSCALL_H__
#define __PLAWNEKJX_SYSCALL_H__

#include <unistd.h>
#include <sys/syscall.h>

#define plawnekjx_syscall_0(n)          plawnekjx_syscall_4 (n, 0, 0, 0, 0)
#define plawnekjx_syscall_1(n, a)       plawnekjx_syscall_4 (n, a, 0, 0, 0)
#define plawnekjx_syscall_2(n, a, b)    plawnekjx_syscall_4 (n, a, b, 0, 0)
#define plawnekjx_syscall_3(n, a, b, c) plawnekjx_syscall_4 (n, a, b, c, 0)

ssize_t plawnekjx_syscall_4 (size_t n, size_t a, size_t b, size_t c, size_t d);

#endif
