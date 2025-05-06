#include "cpu-monitor.hpp"
#include <fstream>
#include <sstream>
#include <thread>
#include <chrono>

using namespace std;

double CPUMonitor::getCPULoad() {
    ifstream file("/proc/stat");
    string line;
    getline(file, line);
    istringstream iss(line);

    string cpu;
    unsigned long long user, nice, system, idle, iowait, irq, softirq, steal;
    iss >> cpu >> user >> nice >> system >> idle >> iowait >> irq >> softirq >> steal;

    static unsigned long long prevTotal = 0, prevIdle = 0;
    unsigned long long total = user + nice + system + idle + iowait + irq + softirq + steal;
    unsigned long long totalDiff = total - prevTotal;
    unsigned long long idleDiff = idle - prevIdle;

    prevTotal = total;
    prevIdle = idle;

    return 1.0 - (static_cast<double>(idleDiff) / totalDiff);
}
