#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include "../automata/aho-corasick.hpp"
#include "../automata/compressed-ac.hpp"
#include "../utils/LCGRandom.hpp"
#include <string>

enum class PacketType { LIGHT, HEAVY };

class PacketProcessor {
public:
    // Take RNG by value and move it in
    PacketProcessor(LCGRandom rng,
                    AhoCorasick& fullMatrixAutomaton,
                    CompressedAC& compressedAutomaton);

    // Classify a single string (already formatted with  src:port->dst:port|payload )
    PacketType classifyPacket(const ACConnectionKey& key,
                              const std::string& packet) const;

    // Returns true if any regex rule matches (for this connection + payload)
    bool processPacket(const std::string& sourceIP,
                       const std::string& destIP,
                       int sourcePort,
                       int destPort,
                       const std::string& payload);

private:
    LCGRandom random_;
    AhoCorasick& fullMatrix_;
    CompressedAC& compressed_;
};

#endif // PACKET_PROCESSOR_HPP
