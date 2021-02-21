#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <asm/unistd.h>
#include <android/log.h>

#include "syscall_arch.h"
#include "syscalls.h"
#include "mylibc.h"

#include "sys/inotify.h"


#define MAX_LINE 512
#define MAX_LENGTH 256
#define MAX_WATCHERS 100
static const char *APPNAME = "DetectDebug";
static const char *PROC_MAPS = "/proc/self/maps";
static const char *PROC_STATUS = "/proc/self/task/%s/status";
static const char *PROC_COMM = "/proc/self/task/%s/comm";
static const char *PROC_TASK_MEM = "/proc/self/task/%s/mem";
static const char *PROC_TASK_PAGEMAP = "/proc/self/task/%s/pagemap";
static const char *PROC_TASK = "/proc/self/task";
static const char *JDWP = "JDWP";
static const char *TRACER_PID = "TracerPid";
static const char *PROC_SELF_STATUS = "/proc/self/status";
static const char *PROC_SELF_PAGEMAP = "/proc/self/pagemap";
static const char *PROC_SELF_MEM = "/proc/self/mem";

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )

static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len);

static inline bool detect_java_debugger();

static inline bool checkforTracerPid(int fd);

static inline bool detect_native_debugger();

static inline int crash(int randomval);

static inline bool detect_fileaccess_for_debugger_memorydump();

void detect_memory_dump_loop(void *pargs);

void detect_debugger_loop(void *pargs);

unsigned int gpCrash = 0xfa91b9cd;

//Upon loading the library, this function annotated as constructor starts executing
__attribute__((constructor))
void detectMemoryAccess() {

    pthread_t t;
    pthread_create(&t, NULL, (void *) detect_debugger_loop, NULL);

    pthread_t t1;
    pthread_create(&t1, NULL, (void *) detect_memory_dump_loop, NULL);

}


void detect_debugger_loop(void *pargs) {

    struct timespec timereq;
    timereq.tv_sec = 1; //Changing to 5 seconds from 1 second
    timereq.tv_nsec = 0;

    while (1) {
        detect_java_debugger();

        detect_native_debugger();

        my_nanosleep(&timereq, NULL);

    }
}

void detect_memory_dump_loop(void *pargs) {
    struct timespec timereq;
    timereq.tv_sec = 1;
    timereq.tv_nsec = 0;

    while (1) {
        detect_fileaccess_for_debugger_memorydump();
        my_nanosleep(&timereq, NULL);
    }
}

__attribute__((always_inline))
static inline bool
detect_java_debugger() {
    DIR *dir = opendir(PROC_TASK);
    bool bRet = false;

    if (dir != NULL) {
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            char filePath[MAX_LENGTH] = "";

            if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                continue;
            }
            snprintf(filePath, sizeof(filePath), PROC_COMM, entry->d_name);
            int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
            if (fd != 0) {
                char buf[MAX_LENGTH] = "";
                read_one_line(fd, buf, MAX_LENGTH);
                if (0 == my_strncmp(buf, JDWP, strlen(JDWP))) {
                    __android_log_print(ANDROID_LOG_WARN, APPNAME, "App is Debuggable");
                    bRet = true;
                }
            }
            my_close(fd);
        }
        closedir(dir);

    }
    return bRet;
}

__attribute__((always_inline))
static inline bool
checkforTracerPid(int fd) {
    bool bRet = false;
    char map[MAX_LINE];
    while ((read_one_line(fd, map, MAX_LINE)) > 0) {

        if (NULL != my_strstr(map, TRACER_PID)) {
            char *saveptr1;
            my_strtok_r(map, ":", &saveptr1);
            int pid = my_atoi(saveptr1);
            if (pid != 0) {
                bRet = true;
            }
            break;
        }
    }

    return bRet;

}

__attribute__((always_inline))
static inline bool
detect_native_debugger() {

    bool bRet = false;
    int fd = my_openat(AT_FDCWD, PROC_SELF_STATUS, O_RDONLY | O_CLOEXEC, 0);
    if (fd != 0) {
        bRet = checkforTracerPid(fd);
        if(bRet){
            __android_log_print(ANDROID_LOG_WARN, APPNAME, "Native Debugger Attached");
        }
        my_close(fd);
    }
    if (!bRet) {

        DIR *dir = opendir(PROC_TASK);

        if (dir != NULL) {
            struct dirent *entry = NULL;
            while ((entry = readdir(dir)) != NULL) {
                char filePath[MAX_LENGTH] = "";

                if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                    continue;
                }
                snprintf(filePath, sizeof(filePath), PROC_STATUS, entry->d_name);

                int fd = my_openat(AT_FDCWD, filePath, O_RDONLY | O_CLOEXEC, 0);
                if (fd != 0) {
                    bRet = checkforTracerPid(fd);
                    if(bRet){
                        __android_log_print(ANDROID_LOG_WARN, APPNAME, "Native Debugger Attached");
                    }
                    my_close(fd);
                }
                if (bRet)
                    break;
            }
            closedir(dir);
        }
    }

    return bRet;

}

__attribute__((always_inline))
static inline bool
detect_fileaccess_for_debugger_memorydump() {
    int length, i = 0;
    int fd;
    int wd[MAX_WATCHERS] = {0,};
    int read_length = 0;
    char buffer[EVENT_BUF_LEN];
    /*creating the INOTIFY instance*/
    fd = my_inotify_init1(0);
    __android_log_print(ANDROID_LOG_WARN, APPNAME, "Notify Init:%d\n",fd);

    if (fd > 0) {

        wd[i++] = my_inotify_add_watch(fd, PROC_SELF_PAGEMAP, IN_ACCESS | IN_OPEN);
        wd[i++] = my_inotify_add_watch(fd, PROC_SELF_MEM, IN_ACCESS | IN_OPEN);
        wd[i++] = my_inotify_add_watch(fd, PROC_MAPS, IN_ACCESS | IN_OPEN);

        DIR *dir = opendir(PROC_TASK);

        if (dir != NULL) {
            struct dirent *entry = NULL;
            while ((entry = readdir(dir)) != NULL) {
                char memPath[MAX_LENGTH] = "";
                char pagemapPath[MAX_LENGTH] = "";

                if (0 == my_strcmp(entry->d_name, ".") || 0 == my_strcmp(entry->d_name, "..")) {
                    continue;
                }
                snprintf(memPath, sizeof(memPath), PROC_TASK_MEM, entry->d_name);
                snprintf(pagemapPath, sizeof(pagemapPath), PROC_TASK_PAGEMAP, entry->d_name);
                wd[i++] = my_inotify_add_watch(fd, memPath, IN_ACCESS | IN_OPEN);
                wd[i++] = my_inotify_add_watch(fd, pagemapPath, IN_ACCESS | IN_OPEN);

            }
            closedir(dir);
        }

        __android_log_print(ANDROID_LOG_WARN, APPNAME, "Completed adding watch\n");

        length = read(fd, buffer, EVENT_BUF_LEN);
        __android_log_print(ANDROID_LOG_WARN, APPNAME, "inotify read %d\n", length);

        if (length > 0) {
            /*actually read return the list of change events happens. Here, read the change event one by one and process it accordingly.*/
            while (read_length < length) {
                struct inotify_event *event = (struct inotify_event *) buffer + read_length;

                if (event->mask & IN_ACCESS) {
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "Unexpected file access..Take action\n");
                    crash(0x3d5f);
                } else if (event->mask & IN_OPEN) {
                    __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                        "Unexpected file open..Take action\n");
                    crash(0x9a3b);
                }
                __android_log_print(ANDROID_LOG_WARN, APPNAME,
                                    "EVENT!!!!:%s\n", event->name);
                read_length += EVENT_SIZE + event->len;
            }
        }

        for (int j = 0; j < i; j++) {
            if (wd[j] != 0) {
                my_inotify_rm_watch(fd, wd[j]);
            }
        }
        /*closing the INOTIFY instance*/
        close(fd);
    } else {
        __android_log_print(ANDROID_LOG_WARN, APPNAME,
                            "iNotify init failed\n");
    }

}


__attribute__((always_inline))
static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    char b;
    ssize_t ret;
    ssize_t bytes_read = 0;

    my_memset(buf, 0, max_len);

    do {
        ret = my_read(fd, &b, 1);

        if (ret != 1) {
            if (bytes_read == 0) {
                // error or EOF
                return -1;
            } else {
                return bytes_read;
            }
        }

        if (b == '\n') {
            return bytes_read;
        }

        *(buf++) = b;
        bytes_read += 1;

    } while (bytes_read < max_len - 1);

    return bytes_read;
}


__attribute__((always_inline))
static inline int crash(int randomval){

    volatile int *p = gpCrash;
    p += randomval;
    p += *p + randomval;
    /* If it still doesnt crash..crash using null pointer */
    p = 0;
    p += *p;

    return *p;
}

