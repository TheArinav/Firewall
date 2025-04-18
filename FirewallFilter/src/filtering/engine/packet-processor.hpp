#ifndef PACKET_PROCESSOR_HPP
#define PACKET_PROCESSOR_HPP

#include "../automata/aho-corasick.hpp"
#include "../automata/compressed-ac.hpp"
#include "../enforcers/ip-port-enforcer.hpp"
#include "../enforcers/payload-length-enforcer.hpp"
#include "../enforcers/regex-enforcer.hpp"
#include "../enforcers/tls-fingerprint-enforcer.hpp"
#include <string>


enum class PacketType { LIGHT, HEAVY };

class PacketProcessor {
public:
    PacketProcessor(AhoCorasick& fullMatrixAutomaton, CompressedAC& compressedAutomaton);

    PacketType classifyPacket(const std::string& payload) const;
    bool processPacket(const std::string& sourceIP, const std::string& destIP, int sourcePort,
                       int destPort, const std::string& payload);

private:
    AhoCorasick& fullMatrixAutomaton;
    CompressedAC& compressedAutomaton;
};

#endif // PACKET_PROCESSOR_HPP
