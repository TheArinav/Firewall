namespace FirewallService.auth;

using FirewallService.auth.structs;
using ipc.structs.GeneralActionStructs;
public class PermissionManager
{
    public PrivilegeMainObject? MainObject;

    public PermissionManager()
    {
        MainObject = PrivilegeMainObject.Load();
    }

    private PermissionCondition GetPermissionForUser(long userID, PermissionType type, string argument)
    {
        var userEntry = MainObject?.UserPrivileges.FirstOrDefault(priv => priv.UserID == userID);
        if (userEntry is null)
            
            return PermissionCondition.Never;
        var match = userEntry.Permissions.FirstOrDefault(cur => 
            cur.type == type && (cur.value == argument || cur.value == "*"));
        return match.Equals(default) 
            ? PermissionCondition.Never 
            : match.condition;
    }
}