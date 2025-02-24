#include "ip-port-enforcer.hpp"

using namespace std;

IpPortEnforcer::IpPortEnforcer(const std::vector<std::string>& allowedSrcIPs, const std::vector<std::string>& allowedDstIPs,
                               const std::vector<int>& allowedSrcPorts, const std::vector<int>& allowedDstPorts)
{
    allowedSources.insert(allowedSrcIPs.begin(), allowedSrcIPs.end());
    allowedDestinations.insert(allowedDstIPs.begin(), allowedDstIPs.end());
    allowedSourcePorts.insert(allowedSrcPorts.begin(), allowedSrcPorts.end());
    allowedDestinationPorts.insert(allowedDstPorts.begin(), allowedDstPorts.end());
}

bool IpPortEnforcer::validate(const std::string& srcIP, const std::string& dstIP, int srcPort, int dstPort) const {
    return (allowedSources.count(srcIP) && allowedDestinations.count(dstIP) &&
            allowedSourcePorts.count(srcPort) && allowedDestinationPorts.count(dstPort));
}
