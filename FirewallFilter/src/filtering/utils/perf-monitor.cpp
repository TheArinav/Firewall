#include "perf-monitor.hpp"
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <iostream>

int start_perf_counter() {
    perf_event_attr pe = {};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.config = PERF_COUNT_HW_CACHE_MISSES;  // Track L2 cache misses
    pe.disabled = 1;

    int fd = syscall(SYS_perf_event_open, &pe, 0, -1, -1, 0);
    if (fd == -1) {
        perror("perf_event_open");
        return -1;
    }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    return fd;
}

long read_perf_counter(int fd) {
    long count;
    read(fd, &count, sizeof(long));
    return count;
}

void stop_perf_counter(int fd) {
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
    close(fd);
}
