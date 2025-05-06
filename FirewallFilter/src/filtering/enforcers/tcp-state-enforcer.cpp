#include "tcp-state-enforcer.hpp"

TCPStateEnforcer::TCPStateEnforcer() : tracker(std::make_unique<ConnectionTracker>()) {}

TCPStateEnforcer& TCPStateEnforcer::operator=(TCPStateEnforcer& other) noexcept
{
    this->tracker = std::move(other.tracker) ;
    return *this;
}


bool TCPStateEnforcer::validate(const std::string& srcIP, const std::string& dstIP,
                                int srcPort, int dstPort,
                                bool syn, bool ack, bool fin, bool rst) const {
    ConnectionKey key{srcIP, dstIP, srcPort, dstPort};
    auto state = (*tracker).updateConnection(key, syn, ack, fin, rst);

    // Only allow valid state progressions
    return state != TCPConnectionState::NONE;
}
