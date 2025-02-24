#include "packet-processor.hpp"
#include "../utils/logger.hpp"
#include "../utils/cpu-monitor.hpp"
#include "../utils/perf-monitor.hpp"

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <iostream>


using namespace std;

PacketProcessor::PacketProcessor(AhoCorasick& fullMatrixAutomaton, CompressedAC& compressedAutomaton)
    : fullMatrixAutomaton(fullMatrixAutomaton), compressedAutomaton(compressedAutomaton) {}

PacketType PacketProcessor::classifyPacket(const string& payload) const {
    double cpuLoad = CPUMonitor::getCPULoad();

    if (cpuLoad < 0.7) {
        // CPU load is low, use full cache-miss tracking
        int perf_fd = start_perf_counter();
        int currentState = 0;
        for (char ch : payload) {
            while (currentState && fullMatrixAutomaton.getStateTransition(currentState, ch) == -1)
                currentState = fullMatrixAutomaton.getFailureLink(currentState);

            currentState = (fullMatrixAutomaton.getStateTransition(currentState, ch) != -1)
                            ? fullMatrixAutomaton.getStateTransition(currentState, ch)
                            : 0;
        }
        long cacheMisses = read_perf_counter(perf_fd);
        stop_perf_counter(perf_fd);

        return (cacheMisses > 1000) ? PacketType::HEAVY : PacketType::LIGHT;
    } else {
        // CPU is overloaded, use rare state tracking
        int currentState = 0;
        int rareStateCount = 0;
        for (char ch : payload) {
            while (currentState && fullMatrixAutomaton.getStateTransition(currentState, ch) == -1)
                currentState = fullMatrixAutomaton.getFailureLink(currentState);

            currentState = (fullMatrixAutomaton.getStateTransition(currentState, ch) != -1)
                            ? fullMatrixAutomaton.getStateTransition(currentState, ch)
                            : 0;

            if (fullMatrixAutomaton.isRareState(currentState)) {
                rareStateCount++;
            }
        }
        return (rareStateCount > payload.size() / 5) ? PacketType::HEAVY : PacketType::LIGHT;
    }
}

bool PacketProcessor::processPacket(const string& sourceIP, const string& destIP, 
                                    int sourcePort, int destPort, const string& payload) {
    PacketType type = classifyPacket(payload);
    Logger::debug("Packet classified as: " + string((type == PacketType::LIGHT) ? "LIGHT" : "HEAVY"));

    if (type == PacketType::LIGHT) {
        return fullMatrixAutomaton.search(payload);
    } else {
        return compressedAutomaton.search(payload);
    }
}
