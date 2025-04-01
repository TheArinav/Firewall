namespace FirewallService.auth.structs;

public enum PermissionType
{
    GetRule,
    GetConnection,
    GetConnectionClass,
    GetPacketInfo,
    GetTunnelKey,
    GetRecord,
    RequestAddRule,
    RequestRuleVerdict,
    RequestDeleteRule,
    RequestProbe,
    RequestRuleAddEnforcer,
    RequestRuleRemoveEnforcer,
    RequestAddProtocol,
    RequestRemoveProtocol,
    RequestSuppressRule,
    RequestSuppressProtocol,
    RequestCreateTunnel,
    RequestDeleteTunnel,
    RequestSetTunnelKey,
    RequestCreateUser,
    RequestDeleteUser,
    RequestUserAddPermission,
    RequestUserRemovePermission,
    RequestCreatePacket
}