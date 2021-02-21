#ifndef DETECTDEBUGGER_SYSCALLS_H
#define DETECTDEBUGGER_SYSCALLS_H

/*
 * System calls such as file operations, sleep are converted to syscalls to avoid easy bypass
 * through readymade scripts hooking onto libc calls.
 */
__attribute__((always_inline))
static inline int my_openat(int __dir_fd, const void *__path, int __flags, int __mode) {
    return (int) __syscall4(__NR_openat, __dir_fd, (long) __path, __flags, __mode);
}

__attribute__((always_inline))
static inline ssize_t my_read(int __fd, void *__buf, size_t __count) {
    return __syscall3(__NR_read, __fd, (long) __buf, (long) __count);
}

__attribute__((always_inline))
static inline int my_close(int __fd) {
    return (int) __syscall1(__NR_close, __fd);
}

__attribute__((always_inline))
static inline int my_nanosleep(const struct timespec *__request, struct timespec *__remainder) {
    return (int) __syscall2(__NR_nanosleep, (long) __request, (long) __remainder);
}

__attribute__((always_inline))
int my_inotify_init1(int flags) {
    return __syscall1(__NR_inotify_init1, flags);
}

__attribute__((always_inline))
int my_inotify_add_watch(int __fd, const char *__path, uint32_t __mask) {
    return __syscall3(__NR_inotify_add_watch, __fd, (long) __path, (long) __mask);
}

__attribute__((always_inline))
int my_inotify_rm_watch(int __fd, uint32_t __watch_descriptor) {
    return __syscall2(__NR_inotify_rm_watch, __fd, (long) __watch_descriptor);
}

#endif //DETECTDEBUGGER_SYSCALLS_H