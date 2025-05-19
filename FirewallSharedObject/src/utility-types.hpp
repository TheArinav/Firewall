#ifndef UTILITY_TYPES_HPP
#define UTILITY_TYPES_HPP

#include <string>

using namespace std;

namespace fwso
{
    enum class DBTables
    {
        Connections,
        ConnectionClass,
        EncryptedTunnelDetectionEnforcer,
        EncryptedTunnelIntegrityEnforcer,
        Enforcer,
        FirewallRule,
        Packet,
        PayloadLengthEnforcer,
        Protocol,
        RateLimitingEnforcer,
        Record,
        RegexEnforcer,
        TCPStateEnforcer,
        TLSFingerprintEnforcer
    };
    enum class DBTableColumns
    {
        Connection_ConnectionID,
        Connection_IPv4Address,
        Connection_IPv6Address,
        Connection_Port,
        Connection_ConnectionClassID,
        ConnectionClass_ClassID,
        ConnectionClass_ClassName,
        ConnectionClass_Description,
        EncryptedTunnelDetectionEnforcer_EnforcerID,
        EncryptedTunnelDetectionEnforcer_MaxEntropy,
        EncryptedTunnelIntegrityEnforcer_EnforcerID,
        EncryptedTunnelIntegrityEnforcer_TunnelType,
        EnforcerID_EnforcerID,
        FirewallRule_RuleID,
        FirewallRule_ConnectionClassID,
        FirewallRule_ProtocolID,
        FirewallRuleEnforcer_RuleID,
        FirewallRuleEnforcer_EnforcerID,
        FirewallRuleEnforcer_EnforcementOrder,
        Packet_PacketID,
        Packet_IPversion,
        Packet_QoS,
        Packet_Checksum,
        Packet_Payload,
        Packet_Source,
        Packet_Destination,
        PayloadLengthEnforcer_EnforcerID,
        PayloadLengthEnforcer_Maximum,
        PayloadLengthEnforcer_Minimum,
        Protocol_ProtocolID,
        Protocol_ProtocolName,
        Protocol_ActiveStatus,
        Protocol_EnforcerID,
        RateLimitingEnforcer_EnforcerID,
        RateLimitingEnforcer_MaxPacketsPerSecond,
        Record_RecordID,
        Record_Verdict,
        Record_Timestamp,
        Record_PacketID,
        Record_RuleID,
        RegexEnforcer_EnforcerID,
        RegexEnforcer_Pattern,
        TCPStateEnforcer_EnforcerID,
        TCPStateEnforcer_IsEnabled,
        TLSFingerprintEnforcer_EnforcerID,
        TLSFingerprintEnforcer_AllowedFingerprints,
        ALL
    };
    namespace helpers
    {
        string SerializeColumn (const DBTableColumns& column);
    }
}

#endif //UTILITY_TYPES_HPP
