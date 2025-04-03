namespace FirewallService.auth.structs;

using Permission = (PermissionType type,PermissionCondition condition, string value);

public class UserPrivileges
{
    public long UserID { get; set; }
    public List<Permission> Permissions { get; set; }

    public static readonly UserPrivileges RootUser = new UserPrivileges(0, [
        (PermissionType.GetRule, PermissionCondition.Always, "*"),
        (PermissionType.GetConnection, PermissionCondition.Always, "*"),
        (PermissionType.GetConnectionClass, PermissionCondition.Always, "*"),
        (PermissionType.GetPacketInfo, PermissionCondition.Always, "*"),
        (PermissionType.GetTunnelKey, PermissionCondition.Always, "*"),
        (PermissionType.GetRecord, PermissionCondition.Always, "*"),
        (PermissionType.GetRule, PermissionCondition.Always, "*"),
        (PermissionType.RequestAddRule, PermissionCondition.Always, "*"),
        (PermissionType.RequestRuleVerdict, PermissionCondition.Always, "*"),
        (PermissionType.RequestDeleteRule, PermissionCondition.Always, "*"),
        (PermissionType.RequestProbe, PermissionCondition.Always, "*"),
        (PermissionType.RequestRuleAddEnforcer, PermissionCondition.Always, "*"),
        (PermissionType.RequestRuleRemoveEnforcer, PermissionCondition.Always, "*"),
        (PermissionType.RequestAddProtocol, PermissionCondition.Always, "*"),
        (PermissionType.RequestRemoveProtocol, PermissionCondition.Always, "*"),
        (PermissionType.RequestSuppressRule, PermissionCondition.Always, "*"),
        (PermissionType.RequestSuppressProtocol, PermissionCondition.Always, "*"),
        (PermissionType.RequestAddRule, PermissionCondition.Always, "*"),
        (PermissionType.RequestDeleteRule, PermissionCondition.Always, "*"),
        (PermissionType.RequestCreateTunnel, PermissionCondition.Always, "*"),
        (PermissionType.RequestDeleteTunnel, PermissionCondition.Always, "*"),
        (PermissionType.RequestSetTunnelKey, PermissionCondition.Always, "*"),
        (PermissionType.RequestDeleteUser, PermissionCondition.Always, "*"),
        (PermissionType.RequestUserAddPermission, PermissionCondition.Always, "*"),
        (PermissionType.RequestUserRemovePermission, PermissionCondition.Always, "*"),
        (PermissionType.RequestCreateUser, PermissionCondition.Always, "*")
    ]);

    public static readonly UserPrivileges FilterUser = new UserPrivileges(1, [
        (PermissionType.GetRule, PermissionCondition.Always, "*"),
        (PermissionType.GetConnection, PermissionCondition.Always, "*"),
        (PermissionType.GetConnectionClass, PermissionCondition.Always, "*"),
        (PermissionType.GetPacketInfo, PermissionCondition.Always, "*"),
        (PermissionType.GetTunnelKey, PermissionCondition.Always, "*"),
        (PermissionType.GetRecord, PermissionCondition.Always, "*"),
        (PermissionType.GetRule, PermissionCondition.Always, "*"),
        (PermissionType.RequestCreatePacket, PermissionCondition.Always, "*")
    ]);

    public static readonly UserPrivileges GuestUser = new UserPrivileges(2, [
        (PermissionType.RequestCreateUser, PermissionCondition.RequestRoot, "client-program")
    ]);

    public UserPrivileges(long UserID, List<Permission> Permissions)
    {
        this.UserID = UserID;
        this.Permissions = Permissions;
    }
}