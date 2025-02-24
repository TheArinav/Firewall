#ifndef PERF_MONITOR_HPP
#define PERF_MONITOR_HPP

int start_perf_counter();
long read_perf_counter(int fd);
void stop_perf_counter(int fd);

#endif // PERF_MONITOR_HPP
