namespace FirewallService.auth.structs;

using Permission = (PermissionType type,string value);

public class UserPrivileges
{
    public long UserID { get; set; }
    public List<Permission> Permissions { get; set; } = new List<Permission>();

    public static readonly UserPrivileges RootUser = new UserPrivileges(0, new List<Permission>
    {
        (PermissionType.GetRule, "*"),
        (PermissionType.GetConnection, "*"),
        (PermissionType.GetConnectionClass, "*"),
        (PermissionType.GetPacketInfo, "*"),
        (PermissionType.GetTunnelKey, "*"),
        (PermissionType.GetRecord, "*"),
        (PermissionType.GetRule, "*"),
        (PermissionType.RequestAddRule, "true"),
        (PermissionType.RequestRuleVerdict, "*"),
        (PermissionType.RequestDeleteRule, "*"),
        (PermissionType.RequestProbe, "true"),
        (PermissionType.RequestRuleAddEnforcer, "*"),
        (PermissionType.RequestRuleRemoveEnforcer, "*"),
        (PermissionType.RequestAddProtocol, "true"),
        (PermissionType.RequestRemoveProtocol, "*"),
        (PermissionType.RequestSuppressRule, "*"),
        (PermissionType.RequestSuppressProtocol, "*"),
        (PermissionType.RequestAddRule, "true"),
        (PermissionType.RequestDeleteRule, "*"),
        (PermissionType.RequestCreateTunnel, "true"),
        (PermissionType.RequestDeleteTunnel, "*"),
        (PermissionType.RequestSetTunnelKey, "*"),
        (PermissionType.RequestDeleteUser, "true"),
        (PermissionType.RequestUserAddPermission, "true"),
        (PermissionType.RequestUserRemovePermission, "true"),
        (PermissionType.RequestCreateUser, "true")
    });

    public static readonly UserPrivileges FilterUser = new UserPrivileges(1, new List<Permission>
    {
        (PermissionType.GetRule, "*"),
        (PermissionType.GetConnection, "*"),
        (PermissionType.GetConnectionClass, "*"),
        (PermissionType.GetPacketInfo, "*"),
        (PermissionType.GetTunnelKey, "*"),
        (PermissionType.GetRecord, "*"),
        (PermissionType.GetRule, "*"),
        (PermissionType.RequestCreatePacket, "true")
    });

    public UserPrivileges(long UserID, List<Permission> Permissions)
    {
        this.UserID = UserID;
        this.Permissions = Permissions;
    }
}