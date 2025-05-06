#ifndef CONNECTION_STATE_HPP
#define CONNECTION_STATE_HPP

#include <string>
#include <chrono>
#include <tuple>

enum class TCPConnectionState {
    NONE,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT,
    CLOSED
};

struct ConnectionKey {
    std::string srcIP;
    std::string dstIP;
    int srcPort;
    int dstPort;

    bool operator==(const ConnectionKey& other) const {
        return srcIP == other.srcIP && dstIP == other.dstIP &&
               srcPort == other.srcPort && dstPort == other.dstPort;
    }

    // Hash function for use in unordered_map
    struct Hash {
        std::size_t operator()(const ConnectionKey& key) const {
            return std::hash<std::string>()(key.srcIP) ^
                   std::hash<std::string>()(key.dstIP) ^
                   std::hash<int>()(key.srcPort) ^
                   std::hash<int>()(key.dstPort);
        }
    };
};

struct ConnectionEntry {
    TCPConnectionState state = TCPConnectionState::NONE;
    std::chrono::steady_clock::time_point lastSeen;
};

#endif // CONNECTION_STATE_HPP
