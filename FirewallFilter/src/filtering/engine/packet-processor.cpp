#include "packet-processor.hpp"
#include "../utils/logger.hpp"
#include "../utils/cpu-monitor.hpp"
#include "../utils/perf-monitor.hpp"
#include <algorithm>
#include <string_view>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>

#define INSPECTED_BYTE_COUNT 32

using namespace std;

PacketProcessor::PacketProcessor(LCGRandom rng,
                                 AhoCorasick& fullMatrixAutomaton,
                                 CompressedAC& compressedAutomaton)
  : random_(std::move(rng))
  , fullMatrix_(fullMatrixAutomaton)
  , compressed_(compressedAutomaton)
{}

PacketType PacketProcessor::classifyPacket(const ACConnectionKey& key,
                                           const string& packet) const {
    if (packet.size() < INSPECTED_BYTE_COUNT) {
        return PacketType::LIGHT;
    }

    // pick a random window of length INSPECTED_BYTE_COUNT
    int maxOffset = max(1, int(packet.size()) - INSPECTED_BYTE_COUNT);
    int offset    = random_.NextInt(0, maxOffset);
    string_view section(packet.c_str() + offset, INSPECTED_BYTE_COUNT);

    double cpuLoad = CPUMonitor::getCPULoad();

    if (cpuLoad < 0.7) {
        // LIGHT path: measure cache misses on a quick AC walk
        int fd = start_perf_counter();
        int state = 0;
        for (unsigned char c : section) {
            state = fullMatrix_.nextState(key, state, c);
        }
        long misses = read_perf_counter(fd);
        stop_perf_counter(fd);

        return (misses > 50) ? PacketType::HEAVY : PacketType::LIGHT;
    } else {
        // HEAVY path: count rare‐state visits
        int state = 0, rareCount = 0;
        for (unsigned char c : section) {
            state = fullMatrix_.nextState(key, state, c);
            if (fullMatrix_.isRareState(key, state)) {
                ++rareCount;
            }
        }
        return (rareCount > INSPECTED_BYTE_COUNT/5)
               ? PacketType::HEAVY : PacketType::LIGHT;
    }
}

bool PacketProcessor::processPacket(const string& sourceIP,
                                    const string& destIP,
                                    int sourcePort,
                                    int destPort,
                                    const string& payload) {
    // Build the per-connection key
    ACConnectionKey key{sourceIP, destIP, sourcePort, destPort};

    // Compose the string fed to the automaton
    string pkt = sourceIP + ":" + to_string(sourcePort)
               + "->" + destIP + ":" + to_string(destPort)
               + "|"  + payload;

    // Classify as LIGHT or HEAVY
    PacketType type = classifyPacket(key, payload);
    Logger::debug(string("Packet classified as: ")
                  + (type == PacketType::LIGHT ? "LIGHT" : "HEAVY"));

    // Run the proper automaton
    auto matches = (type == PacketType::LIGHT)
                 ? fullMatrix_.search(key, payload)
                 : compressed_.search(key, payload);

    // Check each reported MatchTarget against this connection
    for (auto const& m : matches) {
        bool srcOK   = (m.srcIP   == "*" || m.srcIP   == sourceIP);
        bool dstOK   = (m.dstIP   == "*" || m.dstIP   == destIP);
        bool sportOK = (m.srcPort < 0   || m.srcPort == sourcePort);
        bool dportOK = (m.dstPort < 0   || m.dstPort == destPort);
        if (srcOK && dstOK && sportOK && dportOK) {
            Logger::info("Packet matched regex rule: " + m.ruleID);
            return true;
        }
    }

    Logger::warn("Packet dropped: No matching regex rule for this connection.");
    return false;
}
