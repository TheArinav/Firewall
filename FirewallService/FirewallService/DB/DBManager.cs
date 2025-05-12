using FirewallService.ipc.structs;
using FirewallService.ipc.structs.GeneralActionStructs;

namespace FirewallService.DB;

public class DBManager
{
    private string[] validArgs;
    public DBManager()
    {
      string[] validarg1 =
        [
            "Connection.ConnectionID",
            "Connection.IPv4Address",
            "Connection.IPv6Address",
            "Connection.Port",
            "Connection.ConnectionClassID",
            "ConnectionClass.ClassID",
            "ConnectionClass.ClassName",
            "ConnectionClass.Description",
            "EncryptedTunnelDetectionEnforcer.EnforcerID",
            "EncryptedTunnelDetectionEnforcer.MaxEntropy",
            "EncryptedTunnelIntegrityEnforcer.EnforcerID",
            "EncryptedTunnelIntegrityEnforcer.TunnelType",
            "EnforcerID.EnforcerID",
            "FirewallRule.RuleID",
            "FirewallRule.ConnectionClassID",
            "FirewallRule.ProtocolID",
            "FirewallRuleEnforcer.RuleID",
            "FirewallRuleEnforcer.EnforcerID",
            "FirewallRuleEnforcer.EnforcementOrder",
            "Packet.PacketID",
            "Packet.IPversion",
            "Packet.QoS",
            "Packet.Checksum",
            "Packet.Payload",
            "Packet.Source",
            "Packet.Destination",
            "PayloadLengthEnforcer.EnforcerID",
            "PayloadLengthEnforcer.Maximum",
            "PayloadLengthEnforcer.Minimum",
            "Protocol.ProtocolID",
            "Protocol.ProtocolName",
            "Protocol.ActiveStatus",
            "Protocol.EnforcerID",
            "RateLimitingEnforcer.EnforcerID",
            "RateLimitingEnforcer.MaxPacketsPerSecond",
            "Record.RecordID",
            "Record.Verdict",
            "Record.Timestamp",
            "Record.PacketID",
            "Record.RuleID",
            "RegexEnforcer.EnforcerID",
            "RegexEnforcer.Pattern",
            "TCPStateEnforcer.EnforcerID",
            "TCPStateEnforcer.IsEnabled",
            "TLSFingerprintEnforcer.EnforcerID",
            "TLSFingerprintEnforcer.AllowedFingerprints"
            
        ];
        validArgs = (string[])from cur in validarg1 select cur.Split('.').Last(); 
        validArgs = validArgs.Distinct().ToArray();
    }
    public Response HandleRequest(GeneralAction generalActionRequest)
    {
        var queryCondition = "";
        var queryExpression = "";
        var whereIndex = 0;
        var curArg = 0;
        string insteredArg() => $"#{whereIndex}";
        var queryType = generalActionRequest.Prototype switch
        {
            ActionPrototype.Get => "SELECT #1 FROM #2 WHERE #3",
            ActionPrototype.Create => "INSERT (#1) INTO #2 VALUES #4",
            ActionPrototype.Update => "UPDATE #2 SET #1 WHERE #3",
            ActionPrototype.Delete => "DELETE FROM #2 WHERE #3",
            ActionPrototype.Suppress => "UPDATE #2 SET IsActive=False WHERE #3",
            _ => throw new ArgumentOutOfRangeException()
        };
        var queriedObject = generalActionRequest.Subject switch
        {
            ActionSubject.Connection => "Connection",
            ActionSubject.ConnectionClass => "ConnectionClass",
            ActionSubject.Protocol => "Protocol",
            ActionSubject.Rule => "FirewallRule",
            ActionSubject.Record => "Record",
            ActionSubject.Enforcer => "#0Enforcer",
            _ => throw new ArgumentOutOfRangeException()
        };
        if (generalActionRequest.Subject == ActionSubject.Enforcer)
        {
            var flag = int.TryParse(generalActionRequest.Arguments[curArg++], out var type);
            flag = flag && type is >= 0 and < 7;
            if (!flag)
                return new Response(false, "Invalid argument for Enforcer type", null, null);
            var arg0 = type switch
            {
                0 => "EncryptedTunnelDetection",
                1 => "EncryptedTunnelIntegrity",
                2 => "PayloadLength",
                3 => "RateLimiting",
                4 => "Regex",
                5 => "TCPState",
                6 => "TLSFingerprint",
                _ => throw new ArgumentOutOfRangeException()
            };
            queriedObject = queriedObject.Replace(insteredArg(), arg0);
        }
        whereIndex++;
        queryExpression = queryType;
       
        if (curArg == 0)
            queryExpression = queryExpression.Replace("#1", generalActionRequest.Arguments[0]);

        return new Response();
    }
}