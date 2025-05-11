#ifndef TCP_STATE_ENFORCER_HPP
#define TCP_STATE_ENFORCER_HPP

#include <memory>

#include "../tcp/connection-tracker.hpp"
#include <string>

class TCPStateEnforcer {
public:
    TCPStateEnforcer();
    TCPStateEnforcer(TCPStateEnforcer&& other) noexcept {
        tracker = std::move(other.tracker);
    }

    TCPStateEnforcer& operator=(TCPStateEnforcer& other) noexcept;

    TCPStateEnforcer& operator=(TCPStateEnforcer&& other) noexcept {
        tracker = std::move(other.tracker);
        return *this;
    }


    bool validate(const std::string& srcIP, const std::string& dstIP,
                  int srcPort, int dstPort,
                  bool syn, bool ack, bool fin, bool rst) const;

private:
    std::unique_ptr<ConnectionTracker> tracker;
};

#endif // TCP_STATE_ENFORCER_HPP
