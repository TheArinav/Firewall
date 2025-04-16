using FirewallService.ipc.structs.GeneralActionStructs;

namespace FirewallService.auth.structs;

using Permission = (PermissionType type,PermissionCondition condition, string value);

public class UserPrivileges
{
    public long UserID { get; set; }
    public List<Permission> Permissions { get; set; }

    public static readonly UserPrivileges RootUser = new UserPrivileges(
        0,
        (from prototype in Enum.GetValues<ActionPrototype>()
            from subject in Enum.GetValues<ActionSubject>()
            select (new PermissionType(prototype, subject), PermissionCondition.Always, "*")
        ).ToList()
    );

    public static readonly UserPrivileges FilterUser = new UserPrivileges(1, [
        (new (ActionPrototype.Get, ActionSubject.Rule), PermissionCondition.Always, "*"),
        (new (ActionPrototype.Get, ActionSubject.Connection), PermissionCondition.Always, "*"),
        (new (ActionPrototype.Get, ActionSubject.ConnectionClass), PermissionCondition.Always, "*"),
        (new( ActionPrototype.Get, ActionSubject.Packet), PermissionCondition.Always, "*"),
        (new( ActionPrototype.Get, ActionSubject.EncryptedTunnelKey), PermissionCondition.Always, "*"),
        (new( ActionPrototype.Get, ActionSubject.Record), PermissionCondition.Always, "*"),
        (new( ActionPrototype.Create, ActionSubject.Packet), PermissionCondition.Always, "*")
    ]);

    public static readonly UserPrivileges GuestUser = new UserPrivileges(2, [
        ( new( ActionPrototype.Create, ActionSubject.User), PermissionCondition.RequestRoot, "client-program")
    ]);

    public UserPrivileges(long UserID, List<Permission> Permissions)
    {
        this.UserID = UserID;
        this.Permissions = Permissions;
    }
}