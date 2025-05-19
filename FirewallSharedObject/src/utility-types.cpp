#include "utility-types.hpp"

namespace fwso::helpers
{
    string SerializeColumn (const DBTableColumns& column)
    {
        switch (column)
        {
        case DBTableColumns::EncryptedTunnelIntegrityEnforcer_EnforcerID:
        case DBTableColumns::EncryptedTunnelDetectionEnforcer_EnforcerID:
        case DBTableColumns::EnforcerID_EnforcerID:
        case DBTableColumns::FirewallRuleEnforcer_EnforcerID:
        case DBTableColumns::PayloadLengthEnforcer_EnforcerID:
        case DBTableColumns::Protocol_EnforcerID:
        case DBTableColumns::RateLimitingEnforcer_EnforcerID:
        case DBTableColumns::RegexEnforcer_EnforcerID:
        case DBTableColumns::TCPStateEnforcer_EnforcerID:
        case DBTableColumns::TLSFingerprintEnforcer_EnforcerID:
            return "EnforcerID";

        case DBTableColumns::FirewallRule_RuleID:
        case DBTableColumns::FirewallRuleEnforcer_RuleID:
        case DBTableColumns::Record_RuleID:
            return "RuleID";

        case DBTableColumns::FirewallRule_ProtocolID:
        case DBTableColumns::Protocol_ProtocolID:
            return "ProtocolID";

        case DBTableColumns::Packet_PacketID:
        case DBTableColumns::Record_PacketID:
            return "PacketID";

        case DBTableColumns::FirewallRule_ConnectionClassID:
        case DBTableColumns::Connection_ConnectionClassID:
            return "ConnectionClassID";

        case DBTableColumns::Connection_ConnectionID:
            return "ConnectionID";
        case DBTableColumns::Connection_IPv4Address:
            return "IPv4Address";
        case DBTableColumns::Connection_IPv6Address:
            return "IPv6Address";
        case DBTableColumns::Connection_Port:
            return "Port";
        case DBTableColumns::ConnectionClass_ClassID:
            return "ClassID";
        case DBTableColumns::ConnectionClass_ClassName:
            return "ClassName";
        case DBTableColumns::ConnectionClass_Description:
            return "Description";
        case DBTableColumns::FirewallRuleEnforcer_EnforcementOrder:
            return "EnforcementOrder";
        case DBTableColumns::EncryptedTunnelDetectionEnforcer_MaxEntropy:
            return "MaxEntropy";
        case DBTableColumns::EncryptedTunnelIntegrityEnforcer_TunnelType:
            return "TunnelType";
        case DBTableColumns::Packet_IPversion:
            return "IPversion";
        case DBTableColumns::Packet_QoS:
            return  "QoS";
        case DBTableColumns::Packet_Checksum:
            return "Checksum";
        case DBTableColumns::Packet_Payload:
            return "Payload";
        case DBTableColumns::Packet_Source:
            return "Source";
        case DBTableColumns::Packet_Destination:
            return "Destination";
        case DBTableColumns::PayloadLengthEnforcer_Maximum:
            return "Maximum";
        case DBTableColumns::PayloadLengthEnforcer_Minimum:
            return "Minimum";
        case DBTableColumns::Protocol_ProtocolName:
            return "ProtocolName";
        case DBTableColumns::Protocol_ActiveStatus:
            return "ActiveStatus";
        case DBTableColumns::RateLimitingEnforcer_MaxPacketsPerSecond:
            return "MaxPacketsPerSecond";
        case DBTableColumns::Record_RecordID:
            return "RecordID";
        case DBTableColumns::Record_Verdict:
            return "Verdict";
        case DBTableColumns::Record_Timestamp:
            return "Timestamp";
        case DBTableColumns::RegexEnforcer_Pattern:
            return "Pattern";
        case DBTableColumns::TCPStateEnforcer_IsEnabled:
            return  "IsEnabled";
        case DBTableColumns::TLSFingerprintEnforcer_AllowedFingerprints:
            return "AllowedFingerprints";
        case DBTableColumns::ALL:
            return "*";
        }
        return "";
    }
}