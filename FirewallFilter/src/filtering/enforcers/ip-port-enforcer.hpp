#ifndef IP_PORT_ENFORCER_HPP
#define IP_PORT_ENFORCER_HPP

#include <string>
#include <vector>
#include <set>

class IpPortEnforcer {
public:
    IpPortEnforcer() = default;
    IpPortEnforcer(const std::vector<std::string>& allowedSrcIPs, const std::vector<std::string>& allowedDstIPs,
                   const std::vector<int>& allowedSrcPorts, const std::vector<int>& allowedDstPorts);

    bool validate(const std::string& srcIP, const std::string& dstIP, int srcPort, int dstPort) const;

private:
    std::set<std::string> allowedSources;
    std::set<std::string> allowedDestinations;
    std::set<int> allowedSourcePorts;
    std::set<int> allowedDestinationPorts;
};

#endif // IP_PORT_ENFORCER_HPP
